//! Linux and macOS: Unix socket with peer UID checks, `mlock`, no core dumps.

use std::fs;
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

pub type Stream = UnixStream;

/// SEC-2: no core dumps and no ptrace/proc-mem reads by same-user processes.
pub fn harden_process() {
    // SAFETY: plain libc calls with valid constant arguments and a stack-allocated rlimit.
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// SEC-1: pages pinned in RAM until dropped. Only the secret-holding allocation is locked
/// (not `mlockall`, which makes thread stacks fail under the default `RLIMIT_MEMLOCK`).
/// The allocation must not move or be freed while this guard lives.
pub struct LockedRegion {
    addr: usize,
    len: usize,
}

impl LockedRegion {
    /// Best effort: `None` when the kernel refuses (e.g. `RLIMIT_MEMLOCK` too low).
    pub fn new<T>(region: &[T]) -> Option<Self> {
        let len = size_of_val(region);
        let addr = region.as_ptr() as usize;
        // SAFETY: the pointer and length describe a live allocation; mlock only pins its pages.
        (len > 0 && unsafe { libc::mlock(addr as *const _, len) } == 0).then_some(Self { addr, len })
    }
}

impl Drop for LockedRegion {
    fn drop(&mut self) {
        // SAFETY: same range that was locked in `new`; munlock on an unmapped range is harmless.
        unsafe { libc::munlock(self.addr as *const _, self.len) };
    }
}

/// SEC-4: the UID of the process on the other end of a Unix socket.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for writes and `len` matches the buffer size.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: `uid` and `gid` are valid for writes.
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

/// SEC-4: whether the other end of the socket runs as our user (used in both directions).
pub fn peer_is_us(stream: &Stream) -> io::Result<bool> {
    Ok(peer_uid(stream)? == current_uid())
}

/// True when the peer closed the connection; never blocks and never consumes data.
pub fn peer_hung_up(stream: &UnixStream) -> bool {
    let mut b = 0u8;
    // SAFETY: one writable byte; MSG_PEEK leaves the data queued, MSG_DONTWAIT never blocks.
    let n = unsafe {
        libc::recv(stream.as_raw_fd(), (&raw mut b).cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT)
    };
    match n {
        0 => true,
        n if n > 0 => false,
        _ => io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock,
    }
}

/// Sends SIGTERM to a child process we spawned and have not reaped yet.
pub fn terminate(pid: u32) {
    // SAFETY: kill has no memory-safety preconditions; callers only pass unreaped children.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid cannot fail and has no preconditions.
    unsafe { libc::getuid() }
}

pub fn connect(path: &Path) -> io::Result<Stream> {
    UnixStream::connect(path)
}

pub struct Listener(UnixListener);

impl Listener {
    /// Binds the socket, refusing to start when a live daemon holds it (DMN-2) and checking
    /// the parent directory is ours and private (SEC-4).
    pub fn bind(socket: &Path) -> io::Result<Self> {
        let dir = socket.parent().expect("socket path has a parent");
        if !dir.exists() {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        let meta = fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.uid() != current_uid() || meta.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("{} must be a directory owned by you with mode 0700", dir.display()),
            ));
        }
        let listener = match UnixListener::bind(socket) {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                if UnixStream::connect(socket).is_ok() {
                    return Err(io::Error::new(ErrorKind::AddrInUse, "age-agent is already running"));
                }
                fs::remove_file(socket)?;
                UnixListener::bind(socket)?
            }
            Err(e) => return Err(e),
        };
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        Ok(Self(listener))
    }

    pub fn accept(&self) -> io::Result<Stream> {
        self.0.accept().map(|(s, _)| s)
    }
}

pub fn remove_endpoint(socket: &Path) {
    let _ = fs::remove_file(socket);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hang_up_detection() {
        use std::io::Write;
        let (a, mut b) = UnixStream::pair().unwrap();
        assert!(!peer_hung_up(&a));
        b.write_all(b"x").unwrap();
        assert!(!peer_hung_up(&a)); // pending data is not a hang-up, and stays queued
        drop(b);
        assert!(!peer_hung_up(&a)); // the byte is still there to read
        let mut buf = [0u8; 1];
        std::io::Read::read_exact(&mut &a, &mut buf).unwrap();
        assert!(peer_hung_up(&a));
    }

    #[test]
    fn peer_uid_of_socketpair_is_ours() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), current_uid());
        assert!(peer_is_us(&a).unwrap());
    }
}
