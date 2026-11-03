//! LCK-3: wipe identities on screen lock and on suspend, from logind and screensaver signals.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use futures_lite::StreamExt;
use zbus::message::Type;
use zbus::OwnedVariant;
use zbus::{Connection, Message, MessageStream, MatchRule};

use crate::daemon::Daemon;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Trigger {
    ScreenLock,
    Suspend,
    /// `PrepareForSleep(false)`: the system is back; nothing to wipe, but the sleep
    /// inhibitor released for the suspend must be taken again.
    Resume,
}

const SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const LOGIND: &str = "org.freedesktop.login1";

/// Maps a bus signal to the lock trigger it represents, if any.
pub fn classify(msg: &Message) -> Option<Trigger> {
    let header = msg.header();
    let iface = header.interface()?.as_str();
    let member = header.member()?.as_str();
    let body = msg.body();
    match (iface, member) {
        (SESSION_IFACE, "Lock") => Some(Trigger::ScreenLock),
        ("org.freedesktop.login1.Manager", "PrepareForSleep") => {
            Some(if body.deserialize::<bool>().ok()? { Trigger::Suspend } else { Trigger::Resume })
        }
        ("org.freedesktop.DBus.Properties", "PropertiesChanged") => {
            let (changed_iface, changed, _): (String, HashMap<String, OwnedVariant>, Vec<String>) =
                body.deserialize().ok()?;
            let hint = changed.get("LockedHint").and_then(|v| bool::try_from(v).ok())?;
            (changed_iface == SESSION_IFACE && hint).then_some(Trigger::ScreenLock)
        }
        ("org.freedesktop.ScreenSaver" | "org.gnome.ScreenSaver", "ActiveChanged") => {
            body.deserialize::<bool>().ok()?.then_some(Trigger::ScreenLock)
        }
        _ => None,
    }
}

/// Starts one watcher thread per bus. A missing bus (sway, i3, a container) is not an error:
/// the README tells those users to call `age-agent lock` from their idle hook.
pub fn spawn(daemon: Arc<Daemon>, on_screen_lock: bool, on_suspend: bool) {
    for (name, system) in [("system", true), ("session", false)] {
        let daemon = daemon.clone();
        thread::spawn(move || {
            let result = zbus::block_on(watch(&daemon, system, on_screen_lock, on_suspend));
            if let Err(e) = result {
                eprintln!("age-agent: auto-lock: {name} bus unavailable: {e}");
            }
        });
    }
}

/// A logind *delay* inhibitor: suspend and hibernate wait for this fd to close (up to
/// `InhibitDelayMaxSec`, 5 s by default), so the identities are wiped before memory is written
/// to the hibernation image, which `mlock` does not prevent. Best effort: without logind the
/// signal path still locks, just without the guarantee.
async fn inhibit_sleep(conn: &Connection) -> Option<zbus::OwnedFd> {
    let reply = conn
        .call_method(
            Some(LOGIND),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "Inhibit",
            &("sleep", "age-agent", "wiping cached age identities before sleep", "delay"),
        )
        .await;
    let fd = reply.and_then(|m| {
        let body = m.body();
        body.deserialize::<zbus::OwnedFd>()
    });
    match fd {
        Ok(fd) => Some(fd),
        Err(e) => {
            eprintln!("age-agent: auto-lock: no sleep inhibitor: {e}");
            None
        }
    }
}

async fn watch(daemon: &Daemon, system: bool, on_screen_lock: bool, on_suspend: bool) -> zbus::Result<()> {
    let conn = if system { Connection::system().await? } else { Connection::session().await? };
    let rule = if system {
        MatchRule::builder().msg_type(Type::Signal).sender(LOGIND).build()?
    } else {
        MatchRule::builder().msg_type(Type::Signal).member("ActiveChanged").build()?
    };
    // Subscribe first: signals queue while the inhibitor call is in flight.
    let mut stream = MessageStream::for_match_rule(rule, &conn, None).await?;
    let mut inhibitor = if system && on_suspend { inhibit_sleep(&conn).await } else { None };
    while let Some(msg) = stream.next().await {
        match classify(&msg?) {
            Some(Trigger::ScreenLock) if on_screen_lock => daemon.lock(),
            Some(Trigger::Suspend) if on_suspend => {
                daemon.lock();
                inhibitor = None; // wiped: let the sleep proceed
            }
            Some(Trigger::Resume) if system && on_suspend => inhibitor = inhibit_sleep(&conn).await,
            _ => {}
        }
    }
    drop(inhibitor);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(iface: &str, member: &str, body: &(impl serde::Serialize + zbus::zvariant::Type)) -> Message {
        Message::signal("/org/freedesktop/login1/session/_1", iface, member).build(body).unwrap()
    }

    #[test]
    fn logind_lock_and_sleep() {
        assert_eq!(classify(&signal(SESSION_IFACE, "Lock", &())), Some(Trigger::ScreenLock));
        let sleep = "org.freedesktop.login1.Manager";
        assert_eq!(classify(&signal(sleep, "PrepareForSleep", &true)), Some(Trigger::Suspend));
        assert_eq!(classify(&signal(sleep, "PrepareForSleep", &false)), Some(Trigger::Resume));
    }

    #[test]
    fn screensaver_active_only() {
        for iface in ["org.freedesktop.ScreenSaver", "org.gnome.ScreenSaver"] {
            assert_eq!(classify(&signal(iface, "ActiveChanged", &true)), Some(Trigger::ScreenLock));
            assert_eq!(classify(&signal(iface, "ActiveChanged", &false)), None);
        }
    }

    #[test]
    fn locked_hint_property() {
        let props = "org.freedesktop.DBus.Properties";
        let body = |iface: &str, v: bool| {
            let mut m = HashMap::new();
            m.insert("LockedHint".to_string(), OwnedVariant::try_from(zbus::Variant::from(v)).unwrap());
            (iface.to_string(), m, Vec::<String>::new())
        };
        assert_eq!(classify(&signal(props, "PropertiesChanged", &body(SESSION_IFACE, true))), Some(Trigger::ScreenLock));
        assert_eq!(classify(&signal(props, "PropertiesChanged", &body(SESSION_IFACE, false))), None);
        assert_eq!(classify(&signal(props, "PropertiesChanged", &body("other.Iface", true))), None);
    }

    #[test]
    fn unrelated_signals_ignored() {
        assert_eq!(classify(&signal("org.example.Thing", "Lock", &())), None);
    }
}
