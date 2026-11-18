//! LCK-3 on Windows: wipe identities on session lock, user switch, suspend and log-off,
//! from the messages a hidden window receives.
//!
//! Any same-user process can post these messages to the window. The worst it can do is
//! lock the agent, which `age-agent lock` already allows; no message unlocks anything.

use std::sync::Arc;
use std::thread;

use windows_sys::Win32::UI::WindowsAndMessaging::{
    PBT_APMSUSPEND, WM_ENDSESSION, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT,
    WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
};

use crate::daemon::Daemon;
use crate::sys;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Trigger {
    /// The session locked, or its user switched away (console or remote disconnect).
    ScreenLock,
    /// Suspend or hibernate. `VirtualLock` does not keep pages out of the hibernation file;
    /// the wipe runs in the window procedure, which Windows waits for before sleeping.
    Suspend,
    /// Log-off or shutdown: wipe and exit (LCK-4).
    EndSession,
}

/// Maps a window message to the lock trigger it represents, if any.
pub fn classify(msg: u32, wparam: usize) -> Option<Trigger> {
    match (msg, wparam as u32) {
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT) => {
            Some(Trigger::ScreenLock)
        }
        (WM_POWERBROADCAST, PBT_APMSUSPEND) => Some(Trigger::Suspend),
        (WM_ENDSESSION, w) if w != 0 => Some(Trigger::EndSession),
        _ => None,
    }
}

/// Starts the notification window on its own thread. It always runs, even with both
/// triggers off, so log-off still wipes before exit. Its title is the pipe name, so a
/// test can find the window of one particular daemon.
pub fn spawn(daemon: Arc<Daemon>, on_screen_lock: bool, on_suspend: bool) {
    thread::spawn(move || {
        let title = daemon.endpoint().display().to_string();
        let d = daemon.clone();
        let err = sys::run_notification_window(
            &title,
            Box::new(move |msg, wparam| match classify(msg, wparam) {
                Some(Trigger::ScreenLock) if on_screen_lock => d.lock(),
                Some(Trigger::Suspend) if on_suspend => d.lock(),
                Some(Trigger::EndSession) => d.shutdown(),
                _ => {}
            }),
        );
        eprintln!("age-agent: auto-lock unavailable: {err}");
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::{WTS_SESSION_LOGON, WTS_SESSION_UNLOCK};
    use windows_sys::Win32::UI::WindowsAndMessaging::{PBT_APMRESUMEAUTOMATIC, WM_QUERYENDSESSION};

    #[test]
    fn lock_triggers() {
        for w in [WTS_SESSION_LOCK, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT] {
            assert_eq!(classify(WM_WTSSESSION_CHANGE, w as usize), Some(Trigger::ScreenLock));
        }
        assert_eq!(classify(WM_POWERBROADCAST, PBT_APMSUSPEND as usize), Some(Trigger::Suspend));
        assert_eq!(classify(WM_ENDSESSION, 1), Some(Trigger::EndSession));
    }

    #[test]
    fn harmless_messages_ignored() {
        for w in [WTS_SESSION_UNLOCK, WTS_SESSION_LOGON] {
            assert_eq!(classify(WM_WTSSESSION_CHANGE, w as usize), None);
        }
        assert_eq!(classify(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC as usize), None);
        // A cancelled log-off (`WM_ENDSESSION` with FALSE) and the query itself change nothing.
        assert_eq!(classify(WM_ENDSESSION, 0), None);
        assert_eq!(classify(WM_QUERYENDSESSION, 1), None);
    }
}
