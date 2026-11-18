//! Windows: named pipe with SID checks (SEC-5), `VirtualLock`, a locked-down process DACL,
//! session and power notifications (LCK-3) and the native credential prompt (UNL-5).

use std::cell::{Cell, RefCell};
use std::ffi::{OsStr, OsString, c_void};
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_CANCELLED, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, HWND,
    INVALID_HANDLE_VALUE, LPARAM, LRESULT, LocalFree,
    WAIT_OBJECT_0, WAIT_TIMEOUT, WPARAM,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_PACK_GENERIC_CREDENTIALS, CREDUI_INFOW, CREDUIWIN_GENERIC, CredPackAuthenticationBufferW,
    CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode};
use windows_sys::Win32::System::ErrorReporting::{WER_FAULT_REPORTING_FLAG_NOHEAP, WerSetFlags};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
};
use windows_sys::Win32::System::Power::RegisterSuspendResumeNotification;
use windows_sys::Win32::System::RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateProcessW, GetCurrentProcess, INFINITE, OpenProcess, PROCESS_INFORMATION, STARTUPINFOW, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, SetEvent, TerminateProcess, WaitForMultipleObjects,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW, DispatchMessageW, GetMessageW, MSG,
    RegisterClassW, WNDCLASSW,
};
use windows_sys::core::{BOOL, GUID, PWSTR};
use zeroize::Zeroizing;

/// `SYNCHRONIZE` standard right: lets a parent wait on the process.
const SYNCHRONIZE: u32 = 0x0010_0000;
const PIPE_BUFFER: u32 = 64 * 1024 + 4;

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

fn check(ok: BOOL) -> io::Result<()> {
    if ok != 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

fn owned(h: HANDLE) -> io::Result<OwnedHandle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` is a valid handle that we just opened and nobody else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

fn win32_err(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// Reads a NUL-terminated wide string.
///
/// SAFETY: `p` must point to a NUL-terminated UTF-16 string.
unsafe fn from_wide_ptr(p: *const u16) -> OsString {
    let mut len = 0;
    // SAFETY: the caller guarantees a terminating NUL, so every read is in bounds.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units were just read from `p`.
    OsString::from_wide(unsafe { std::slice::from_raw_parts(p, len) })
}

/// Memory from `LocalAlloc`, freed on drop.
struct LocalBox(*mut c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        // SAFETY: the pointer came from an API that allocates with LocalAlloc, and is freed once.
        unsafe { LocalFree(self.0) };
    }
}

fn security_descriptor(sddl: &str) -> io::Result<LocalBox> {
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: valid NUL-terminated SDDL string and a writable out-pointer.
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
    })?;
    Ok(LocalBox(sd))
}

/// A process token's `TOKEN_USER`, in a pointer-aligned buffer.
struct TokenUserBuf(Vec<usize>);

impl TokenUserBuf {
    fn of(process: HANDLE) -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: `process` is a valid process handle with at least QUERY_LIMITED_INFORMATION.
        check(unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) })?;
        let token = owned(token)?;
        let mut len = 0u32;
        // SAFETY: size query with a null buffer; fails with ERROR_INSUFFICIENT_BUFFER and sets `len`.
        unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut len) };
        let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
        // SAFETY: `buf` holds at least `len` writable, pointer-aligned bytes.
        check(unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
        })?;
        Ok(Self(buf))
    }

    fn sid(&self) -> *mut c_void {
        // SAFETY: GetTokenInformation(TokenUser) filled the buffer with a TOKEN_USER whose SID
        // points inside the same buffer, which lives as long as `self`.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

fn current_user() -> io::Result<TokenUserBuf> {
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing.
    TokenUserBuf::of(unsafe { GetCurrentProcess() })
}

/// The current user's SID as a string, e.g. `S-1-5-21-…-1001`.
pub fn current_sid() -> io::Result<String> {
    let user = current_user()?;
    let mut s: PWSTR = null_mut();
    // SAFETY: `user.sid()` is a valid SID; the output is LocalAlloc'd and freed by `LocalBox`.
    check(unsafe { ConvertSidToStringSidW(user.sid(), &mut s) })?;
    let _free = LocalBox(s.cast());
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated string.
    Ok(unsafe { from_wide_ptr(s) }.to_string_lossy().into_owned())
}

/// Whether process `pid` runs as the current user. A process we may not even query (another
/// user's, a system process) is not ours.
pub fn same_user(pid: u32) -> io::Result<bool> {
    // SAFETY: OpenProcess has no memory preconditions; failure is checked below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    let process = match owned(h) {
        Ok(p) => p,
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => return Ok(false),
        Err(e) => return Err(e),
    };
    let theirs = match TokenUserBuf::of(process.as_raw_handle()) {
        Ok(t) => t,
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => return Ok(false),
        Err(e) => return Err(e),
    };
    let ours = current_user()?;
    // SAFETY: both pointers are valid SIDs inside live buffers.
    Ok(unsafe { EqualSid(theirs.sid(), ours.sid()) } != 0)
}

/// SEC-2: no crash dialogs, no heap in Windows Error Reporting dumps, and a process DACL
/// that keeps same-user processes from reading our memory, injecting threads or opening us
/// for debugging. The "Owner Rights" entry caps what our own user, as the owner, may do;
/// without it the owner could rewrite the DACL. Administrators with `SeDebugPrivilege` are
/// out of scope.
pub fn harden_process() {
    // SAFETY: plain flag setters with constant arguments.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
    }
    if let Err(e) = protect_process() {
        eprintln!("age-agent: warning: could not restrict process access: {e}");
    }
}

/// What same-user processes may still do to us: wait on us, query our identity (the pipe
/// peer checks need it) and terminate us.
pub const PROCESS_ALLOWED: u32 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE;

fn protect_process() -> io::Result<()> {
    let sid = current_sid()?;
    let a = PROCESS_ALLOWED;
    let sd = security_descriptor(&format!("D:P(A;;0x{a:x};;;OW)(A;;0x{a:x};;;{sid})(A;;0x{a:x};;;SY)"))?;
    let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
    // SAFETY: `sd` is a valid self-relative descriptor; the DACL pointer points into it.
    check(unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) })?;
    // SAFETY: the pseudo handle has WRITE_DAC on ourselves; `dacl` is valid while `sd` lives.
    let rc = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if rc != 0 { Err(win32_err(rc)) } else { Ok(()) }
}

/// SEC-1: pages pinned in RAM until dropped. The allocation must not move or be freed while
/// this guard lives.
pub struct LockedRegion {
    addr: usize,
    len: usize,
}

impl LockedRegion {
    /// Best effort: `None` when the working-set quota does not allow it.
    pub fn new<T>(region: &[T]) -> Option<Self> {
        let len = size_of_val(region);
        let addr = region.as_ptr() as usize;
        // SAFETY: the pointer and length describe a live allocation; VirtualLock only pins pages.
        (len > 0 && unsafe { VirtualLock(addr as *const c_void, len) } != 0).then_some(Self { addr, len })
    }
}

impl Drop for LockedRegion {
    fn drop(&mut self) {
        // SAFETY: same range that was locked in `new`.
        unsafe { VirtualUnlock(self.addr as *const c_void, self.len) };
    }
}

/// Terminates a child process we spawned and have not reaped yet.
pub fn terminate(pid: u32) {
    // SAFETY: OpenProcess/TerminateProcess have no memory preconditions; failures are ignored.
    unsafe {
        if let Ok(h) = owned(OpenProcess(PROCESS_TERMINATE, 0, pid)) {
            TerminateProcess(h.as_raw_handle(), 1);
        }
    }
}

/// Starts `exe args…` in `dir` inheriting no handle at all. `std::process::Command` passes
/// `bInheritHandles = TRUE`, which hands the child every inheritable handle we hold, such
/// as the stdio pipes of the age client that started the plugin. A daemon holding those
/// open would keep that client waiting for end-of-file forever. The child has no std
/// handles; Rust's stdio treats that as a sink.
pub fn spawn_detached(exe: &Path, args: &[&str], dir: &Path, flags: u32) -> io::Result<()> {
    let mut cmdline = format!("\"{}\"", exe.display());
    for a in args {
        debug_assert!(!a.contains(['"', ' ']), "arguments are fixed words");
        cmdline.push(' ');
        cmdline.push_str(a);
    }
    let mut cmdline = wide(&cmdline);
    let (exe, dir) = (wide(exe), wide(dir));
    let si = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, ..Default::default() };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: valid NUL-terminated strings (the command line is mutable, as required) and
    // structures that outlive the call.
    check(unsafe {
        CreateProcessW(exe.as_ptr(), cmdline.as_mut_ptr(), null(), null(), 0, flags, null(), dir.as_ptr(), &si, &mut pi)
    })?;
    // We never wait on the child: close both handles at once.
    drop((owned(pi.hProcess), owned(pi.hThread)));
    Ok(())
}

static CTRL_HANDLER: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> BOOL {
    if let Some(f) = CTRL_HANDLER.get() {
        f();
    }
    1
}

/// Runs `f` on Ctrl-C, Ctrl-Break and console close (the Windows counterpart of SIGINT and
/// SIGTERM). Log-off and shutdown arrive as `WM_ENDSESSION` on the notification window.
pub fn on_console_ctrl(f: impl Fn() + Send + Sync + 'static) {
    if CTRL_HANDLER.set(Box::new(f)).is_ok() {
        // SAFETY: `ctrl_handler` is a valid handler for the process lifetime.
        unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };
    }
}

/// Program Files directories, from the shell's known folders rather than the environment.
pub fn program_files_dirs() -> Vec<PathBuf> {
    [FOLDERID_ProgramFilesX86, FOLDERID_ProgramFiles].iter().filter_map(known_folder).collect()
}

fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut p: PWSTR = null_mut();
    // SAFETY: valid GUID and out-pointer; the result is freed with CoTaskMemFree either way.
    let hr = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut p) };
    // SAFETY: on success `p` is a NUL-terminated string.
    let path = (hr >= 0 && !p.is_null()).then(|| PathBuf::from(unsafe { from_wide_ptr(p) }));
    // SAFETY: CoTaskMemFree accepts null.
    unsafe { CoTaskMemFree(p.cast()) };
    path
}

// ---------------------------------------------------------------------------------------
// Named pipe transport (SEC-5)
// ---------------------------------------------------------------------------------------

/// Runs one overlapped operation to completion. It ends early on `cancel` (when given) or
/// after `timeout_ms`, and in every case returns only once the kernel is done with the
/// OVERLAPPED and the buffer `start` handed it.
fn overlapped(
    h: HANDLE,
    cancel: Option<HANDLE>,
    timeout_ms: u32,
    start: impl FnOnce(*mut OVERLAPPED) -> BOOL,
) -> io::Result<u32> {
    // SAFETY: manual-reset, unnamed event with default security.
    let event = owned(unsafe { CreateEventW(null(), 1, 0, null()) })?;
    let mut ov = OVERLAPPED { hEvent: event.as_raw_handle(), ..Default::default() };
    let mut n = 0u32;
    if start(&mut ov) == 0 {
        // SAFETY: no preconditions.
        let err = unsafe { GetLastError() };
        if err != ERROR_IO_PENDING {
            return Err(win32_err(err));
        }
        let mut handles = vec![ov.hEvent];
        handles.extend(cancel);
        // SAFETY: valid handles that outlive the wait.
        let w = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout_ms) };
        if w != WAIT_OBJECT_0 {
            // SAFETY: cancels only this operation on this handle.
            unsafe { CancelIoEx(h, &ov) };
        }
        // SAFETY: waits for the (possibly cancelled) operation, so `ov` outlives it.
        if unsafe { GetOverlappedResult(h, &ov, &mut n, 1) } == 0 {
            let e = io::Error::last_os_error();
            return Err(match w {
                WAIT_OBJECT_0 => e,
                WAIT_TIMEOUT => io::Error::new(ErrorKind::TimedOut, "pipe operation timed out"),
                _ => io::Error::new(ErrorKind::ConnectionAborted, "pipe shut down"),
            });
        }
        return Ok(n);
    }
    // SAFETY: completed synchronously; this only reads the byte count.
    check(unsafe { GetOverlappedResult(h, &ov, &mut n, 1) })?;
    Ok(n)
}

struct Pipe {
    handle: OwnedHandle,
    /// Signalled by `shutdown`: ends pending and future operations on every clone.
    cancel: OwnedHandle,
    read_timeout_ms: AtomicU32,
    server: bool,
}

/// One end of a named pipe connection. Clones share the handle, like a duplicated socket.
pub struct Stream(Arc<Pipe>);

impl Stream {
    fn new(handle: OwnedHandle, server: bool) -> io::Result<Self> {
        // SAFETY: manual-reset, unnamed event with default security.
        let cancel = owned(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        Ok(Self(Arc::new(Pipe { handle, cancel, read_timeout_ms: AtomicU32::new(INFINITE), server })))
    }

    fn raw(&self) -> HANDLE {
        self.0.handle.as_raw_handle()
    }

    fn op(&self, timeout_ms: u32, start: impl FnOnce(HANDLE, *mut OVERLAPPED) -> BOOL) -> io::Result<u32> {
        let h = self.raw();
        overlapped(h, Some(self.0.cancel.as_raw_handle()), timeout_ms, |ov| start(h, ov))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.clone()))
    }

    /// Ends pending and future reads (which then return end-of-file) and writes on every
    /// clone of this connection. The handle itself closes with the last clone.
    pub fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        // SAFETY: valid event handle.
        check(unsafe { SetEvent(self.0.cancel.as_raw_handle()) })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        let ms = timeout.map_or(INFINITE, |d| d.as_millis().clamp(1, INFINITE as u128 - 1) as u32);
        self.0.read_timeout_ms.store(ms, Ordering::Relaxed);
        Ok(())
    }
}

fn is_pipe_end(e: &io::Error) -> bool {
    e.kind() == ErrorKind::ConnectionAborted
        || [ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, ERROR_NO_DATA].map(|c| c as i32).contains(&e.raw_os_error().unwrap_or(0))
}

impl Read for &Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (ptr, len) = (buf.as_mut_ptr(), buf.len().min(u32::MAX as usize) as u32);
        let timeout = self.0.read_timeout_ms.load(Ordering::Relaxed);
        // SAFETY: `buf` stays borrowed until `op` returns, which is after the read completes.
        match self.op(timeout, |h, ov| unsafe { ReadFile(h, ptr, len, null_mut(), ov) }) {
            Ok(n) => Ok(n as usize),
            Err(e) if is_pipe_end(&e) => Ok(0),
            Err(e) => Err(e),
        }
    }
}

impl Write for &Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (ptr, len) = (buf.as_ptr(), buf.len().min(u32::MAX as usize) as u32);
        // SAFETY: `buf` stays borrowed until `op` returns, which is after the write completes.
        self.op(INFINITE, |h, ov| unsafe { WriteFile(h, ptr, len, null_mut(), ov) }).map(|n| n as usize)
    }

    /// Writes complete into the pipe buffer; `FlushFileBuffers` would block until the peer
    /// has read everything, which a stalled peer could make last forever.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// SEC-5: whether the process at the other end runs as our user. The daemon checks the
/// client's token; the client checks the token of the process that created the pipe.
pub fn peer_is_us(stream: &Stream) -> io::Result<bool> {
    let mut pid = 0u32;
    // SAFETY: valid pipe handle and out-pointer.
    check(unsafe {
        match stream.0.server {
            true => GetNamedPipeClientProcessId(stream.raw(), &mut pid),
            false => GetNamedPipeServerProcessId(stream.raw(), &mut pid),
        }
    })?;
    same_user(pid)
}

/// True when the peer closed the connection; never blocks and never consumes data.
pub fn peer_hung_up(stream: &Stream) -> bool {
    let mut avail = 0u32;
    // SAFETY: a zero-length peek with valid out-pointers.
    unsafe { PeekNamedPipe(stream.raw(), null_mut(), 0, null_mut(), &mut avail, null_mut()) == 0 }
}

/// Connects as a client. Identification-level impersonation only: the server may learn who
/// we are but can never act as us. Waits briefly while every instance is busy.
pub fn connect(path: &Path) -> io::Result<Stream> {
    let name = wide(path);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: valid NUL-terminated name; the returned handle is checked by `owned`.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        match owned(h) {
            Ok(h) => return Stream::new(h, false),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && Instant::now() < deadline => {
                // SAFETY: valid name; just waits for a free instance.
                unsafe { WaitNamedPipeW(name.as_ptr(), 500) };
            }
            Err(e) => return Err(e),
        }
    }
}

pub struct Listener {
    name: Vec<u16>,
    path: PathBuf,
    sd: LocalBox,
    /// The instance waiting for the next client. Created before the previous client is
    /// handed off, so there is always one and clients never see "no such pipe".
    next: Cell<Option<OwnedHandle>>,
}

impl Listener {
    /// SEC-5 and DMN-2: creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so
    /// a pipe that already exists (a running daemon, or someone squatting the name) is never
    /// joined. The DACL grants access to our SID only.
    pub fn bind(path: &Path) -> io::Result<Self> {
        let sd = security_descriptor(&format!("D:P(A;;GA;;;{})", current_sid()?))?;
        let l = Listener { name: wide(path), path: path.to_owned(), sd, next: Cell::new(None) };
        match l.create(true) {
            Ok(h) => {
                l.next.set(Some(h));
                Ok(l)
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => Err(l.in_use()),
            Err(e) => Err(e),
        }
    }

    fn in_use(&self) -> io::Error {
        match connect(&self.path).and_then(|s| peer_is_us(&s)) {
            Ok(true) => io::Error::new(ErrorKind::AddrInUse, "age-agent is already running"),
            _ => io::Error::new(
                ErrorKind::PermissionDenied,
                format!("{} is held by another user's process; refusing to start", self.path.display()),
            ),
        }
    }

    fn create(&self, first: bool) -> io::Result<OwnedHandle> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: 0,
        };
        let open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: valid name and security attributes that outlive the call.
        owned(unsafe {
            CreateNamedPipeW(self.name.as_ptr(), open, mode, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER, PIPE_BUFFER, 0, &sa)
        })
    }

    pub fn accept(&self) -> io::Result<Stream> {
        loop {
            let h = match self.next.take() {
                Some(h) => h,
                None => self.create(false)?,
            };
            let raw = h.as_raw_handle();
            // SAFETY: valid pipe handle; `overlapped` waits for completion.
            let r = overlapped(raw, None, INFINITE, |ov| unsafe { ConnectNamedPipe(raw, ov) });
            match r {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) => {}
                // The client came and went before we noticed: drop this instance, try again.
                Err(e) if e.raw_os_error() == Some(ERROR_NO_DATA as i32) => continue,
                Err(e) => return Err(e),
            }
            if let Ok(next) = self.create(false) {
                self.next.set(Some(next));
            }
            return Stream::new(h, true);
        }
    }
}

/// Pipes vanish with their last handle; there is nothing to remove.
pub fn remove_endpoint(_path: &Path) {}

// ---------------------------------------------------------------------------------------
// Session and power notifications (LCK-3)
// ---------------------------------------------------------------------------------------

type MessageHandler = Box<dyn Fn(u32, usize)>;

thread_local! {
    static ON_MESSAGE: RefCell<Option<MessageHandler>> = const { RefCell::new(None) };
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    ON_MESSAGE.with(|h| {
        if let Some(f) = h.borrow().as_ref() {
            f(msg, wparam);
        }
    });
    // SAFETY: forwarding the message we were given to the default procedure.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Creates a hidden top-level window titled `title` (message-only windows miss the power
/// broadcasts), registers it for session-change and suspend notifications, and runs its
/// message loop on this thread, calling `on_message(msg, wparam)` synchronously for every
/// message: the system waits for the window procedure, so a wipe there finishes before
/// the session locks or the machine sleeps. Returns only on failure.
pub fn run_notification_window(title: &str, on_message: MessageHandler) -> io::Error {
    ON_MESSAGE.with(|h| *h.borrow_mut() = Some(on_message));
    let class = wide("age-agent-notify");
    // SAFETY: null module name means this executable.
    let instance = unsafe { GetModuleHandleW(null()) };
    let wc = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        // SAFETY: WNDCLASSW is plain data for which all-zero is a valid "unset" value.
        ..unsafe { std::mem::zeroed() }
    };
    // SAFETY: `wc` and the class name outlive the call. Failure (e.g. already registered by
    // another thread) surfaces in CreateWindowExW below.
    unsafe { RegisterClassW(&wc) };
    let title = wide(title);
    // SAFETY: registered class, valid strings; a zero style keeps the window hidden.
    let hwnd = unsafe {
        CreateWindowExW(0, class.as_ptr(), title.as_ptr(), 0, 0, 0, 0, 0, null_mut(), null_mut(), instance, null())
    };
    if hwnd.is_null() {
        return io::Error::last_os_error();
    }
    // SAFETY: `hwnd` is our live window. Failures only cost the notification they register.
    unsafe {
        if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
            eprintln!("age-agent: auto-lock: no session notifications: {}", io::Error::last_os_error());
        }
        // Modern Standby machines report suspend only to registered recipients.
        RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE);
    }
    // SAFETY: MSG is plain data; GetMessageW fills it.
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    // SAFETY: standard message loop on the thread that owns the window.
    while unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) } > 0 {
        unsafe { DispatchMessageW(&msg) };
    }
    io::Error::other("notification window message loop ended")
}

// ---------------------------------------------------------------------------------------
// Native credential prompt (UNL-5)
// ---------------------------------------------------------------------------------------

/// The buffer CredUI returns, zeroized and freed on drop.
struct CoTaskSecret(*mut c_void, u32);

impl Drop for CoTaskSecret {
    fn drop(&mut self) {
        for i in 0..self.1 as usize {
            // SAFETY: CredUI allocated `self.1` bytes at `self.0`.
            unsafe { std::ptr::write_volatile(self.0.cast::<u8>().add(i), 0) };
        }
        // SAFETY: allocated by CredUI with CoTaskMemAlloc, freed once.
        unsafe { CoTaskMemFree(self.0) };
    }
}

/// Shows the Windows credential dialog with the user name prefilled, so only the
/// passphrase is typed. `Ok(None)` when the user cancels.
pub fn credential_prompt(caption: &str, message: &str) -> io::Result<Option<Zeroizing<String>>> {
    let (caption, message) = (wide(caption), wide(message));
    let info = CREDUI_INFOW {
        cbSize: size_of::<CREDUI_INFOW>() as u32,
        hwndParent: null_mut(),
        pszMessageText: message.as_ptr(),
        pszCaptionText: caption.as_ptr(),
        hbmBanner: null_mut(),
    };
    let (user, empty) = (wide("age-agent"), [0u16]);
    let mut in_len = 0u32;
    // SAFETY: size query; fails with ERROR_INSUFFICIENT_BUFFER and sets `in_len`.
    unsafe { CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, user.as_ptr(), empty.as_ptr(), null_mut(), &mut in_len) };
    let mut packed = vec![0u8; in_len as usize];
    // SAFETY: `packed` has `in_len` writable bytes.
    check(unsafe {
        CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, user.as_ptr(), empty.as_ptr(), packed.as_mut_ptr(), &mut in_len)
    })?;
    let (mut package, mut out, mut out_len) = (0u32, null_mut(), 0u32);
    // SAFETY: all pointers are valid for the call; the output is owned by `CoTaskSecret`.
    let rc = unsafe {
        CredUIPromptForWindowsCredentialsW(
            &info, 0, &mut package, packed.as_ptr().cast(), in_len, &mut out, &mut out_len, null_mut(), CREDUIWIN_GENERIC,
        )
    };
    if rc == ERROR_CANCELLED {
        return Ok(None);
    }
    if rc != 0 {
        return Err(win32_err(rc));
    }
    let out = CoTaskSecret(out, out_len);
    let mut name = [0u16; 514];
    let mut domain = [0u16; 338];
    let mut pass = Zeroizing::new(vec![0u16; 4096]);
    let (mut name_len, mut domain_len, mut pass_len) = (name.len() as u32, domain.len() as u32, pass.len() as u32);
    // SAFETY: every buffer is writable for the length passed with it.
    check(unsafe {
        CredUnPackAuthenticationBufferW(
            0,
            out.0,
            out.1,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            pass.as_mut_ptr(),
            &mut pass_len,
        )
    })?;
    drop(out);
    let units = &pass[..pass.iter().position(|&c| c == 0).unwrap_or(pass.len())];
    // Sized for the worst case (3 UTF-8 bytes per UTF-16 unit), so it never reallocates.
    let mut s = Zeroizing::new(String::with_capacity(units.len() * 3));
    for c in char::decode_utf16(units.iter().copied()) {
        s.push(c.map_err(|_| io::Error::new(ErrorKind::InvalidData, "passphrase is not valid UTF-16"))?);
    }
    Ok(Some(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn pipe_name(tag: &str) -> PathBuf {
        PathBuf::from(format!(r"\\.\pipe\age-agent-unittest-{tag}-{}", std::process::id()))
    }

    fn pair(tag: &str) -> (Listener, Stream, Stream) {
        let path = pipe_name(tag);
        let l = Listener::bind(&path).unwrap();
        let client = connect(&path).unwrap();
        let server = l.accept().unwrap();
        (l, server, client)
    }

    #[test]
    fn sid_and_same_user() {
        let sid = current_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        assert!(same_user(std::process::id()).unwrap());
        // PID 4 is the System process: never ours.
        assert!(!same_user(4).unwrap());
    }

    #[test]
    fn virtual_lock() {
        let v = vec![7u8; 4096];
        assert!(LockedRegion::new(&v).is_some());
        assert!(LockedRegion::new::<u8>(&[]).is_none());
    }

    #[test]
    fn round_trip_and_peer_checks() {
        let (_l, mut server, mut client) = pair("rt");
        assert!(peer_is_us(&server).unwrap());
        assert!(peer_is_us(&client).unwrap());
        client.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").unwrap();
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[test]
    fn hang_up_detection() {
        let (_l, mut server, mut client) = pair("hup");
        assert!(!peer_hung_up(&server));
        client.write_all(b"x").unwrap();
        assert!(!peer_hung_up(&server));
        drop(client);
        let mut buf = [0u8; 1];
        let _ = server.read(&mut buf);
        assert!(peer_hung_up(&server));
        assert_eq!(server.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn shutdown_ends_a_blocked_read() {
        let (_l, _server, client) = pair("shut");
        let handle = client.try_clone().unwrap();
        let t = thread::spawn(move || {
            let mut buf = [0u8; 1];
            (&client).read(&mut buf).unwrap()
        });
        thread::sleep(Duration::from_millis(100));
        handle.shutdown(Shutdown::Both).unwrap();
        assert_eq!(t.join().unwrap(), 0);
    }

    #[test]
    fn read_timeout() {
        let (_l, _server, client) = pair("timeout");
        client.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let t0 = Instant::now();
        let err = (&client).read(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn second_listener_is_refused() {
        let path = pipe_name("dup");
        let _l = Listener::bind(&path).unwrap();
        let err = Listener::bind(&path).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::AddrInUse, "{err}");
    }

    #[test]
    fn many_clients() {
        let path = pipe_name("many");
        let l = Listener::bind(&path).unwrap();
        let p = path.clone();
        let clients = thread::spawn(move || (0..8).map(|_| connect(&p).unwrap()).collect::<Vec<_>>());
        let servers: Vec<_> = (0..8).map(|_| l.accept().unwrap()).collect();
        assert_eq!(clients.join().unwrap().len(), 8);
        assert_eq!(servers.len(), 8);
    }
}
