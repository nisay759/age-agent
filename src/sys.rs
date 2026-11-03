//! The only module with `unsafe` code (SEC-9): process hardening and peer credentials.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

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

/// Overwrites the stack below the caller's frame, where callees that just returned left
/// copies of secrets (parsing an identity moves 32-byte keys through several frames).
/// Best effort, like libsodium's `sodium_stackzero`: the frames are reused, not reserved.
#[inline(never)]
pub fn stack_zero() {
    let mut buf = [0u8; 128 * 1024];
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusively borrowed byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::hint::black_box(&buf);
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid cannot fail and has no preconditions.
    unsafe { libc::getuid() }
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
    }
}
