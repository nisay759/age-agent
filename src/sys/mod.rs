//! The only module with `unsafe` code (SEC-9): process hardening, locked memory, the local
//! transport (Unix socket or named pipe) with its peer checks, and the Windows UI and
//! notification calls. Each platform file exposes the same names.
//!
//! - `harden_process`, `LockedRegion`, `terminate`
//! - `Stream` (`Read + Write`, `try_clone`, `shutdown`, `set_read_timeout`), `connect`,
//!   `peer_is_us`, `peer_hung_up`
//! - `Listener::bind` / `accept`, `remove_endpoint`

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

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
