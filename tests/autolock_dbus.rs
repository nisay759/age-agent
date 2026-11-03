//! LCK-3 end to end: the real daemon on private D-Bus buses, with a fake logind (owning
//! `org.freedesktop.login1`) and a fake screensaver. Skips when `dbus-daemon` is missing.

mod common;

use std::collections::HashMap;
use std::io::{ErrorKind, PipeReader, Read};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, thread};

use common::*;
use zbus::{Connection, OwnedVariant, Variant};

const SESSION_PATH: &str = "/org/freedesktop/login1/session/_1";
const LOGIN_PATH: &str = "/org/freedesktop/login1";

struct Bus {
    child: Child,
    addr: String,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_bus(sock: &Path) -> Option<Bus> {
    let addr = format!("unix:path={}", sock.display());
    let child = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--nopidfile", &format!("--address={addr}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let t0 = Instant::now();
    while !sock.exists() {
        assert!(t0.elapsed() < Duration::from_secs(5), "dbus-daemon did not start");
        thread::sleep(Duration::from_millis(20));
    }
    Some(Bus { child, addr })
}

fn connect(bus: &Bus) -> Connection {
    zbus::block_on(async { zbus::connection::Builder::address(bus.addr.as_str()).build().await }).unwrap()
}

fn emit(conn: &Connection, path: &str, iface: &str, member: &str, body: &(impl serde::Serialize + zbus::zvariant::Type)) {
    zbus::block_on(conn.emit_signal(None::<&str>, path, iface, member, body)).unwrap();
}

/// The part of logind's Manager that the daemon calls: `Inhibit` hands out the write end of a
/// pipe, so the test can see whether the daemon still holds the inhibitor.
#[derive(Clone, Default)]
struct FakeLogind {
    inhibits: Arc<Mutex<Vec<(String, String, String, String)>>>,
    holders: Arc<Mutex<Vec<PipeReader>>>,
}

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl FakeLogind {
    fn inhibit(&self, what: String, who: String, why: String, mode: String) -> zbus::fdo::Result<zbus::OwnedFd> {
        let (r, w) = std::io::pipe().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        self.inhibits.lock().unwrap().push((what, who, why, mode));
        self.holders.lock().unwrap().push(r);
        Ok(zbus::OwnedFd::from(std::os::fd::OwnedFd::from(w)))
    }
}

impl FakeLogind {
    fn inhibit_calls(&self) -> Vec<(String, String, String, String)> {
        self.inhibits.lock().unwrap().clone()
    }

    /// Whether the daemon still holds the `n`th inhibitor fd (the pipe still has a writer).
    fn held(&self, n: usize) -> bool {
        let holders = self.holders.lock().unwrap();
        let r = &holders[n];
        // SAFETY: fcntl on a valid fd we own.
        unsafe { libc::fcntl(r.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        let mut b = [0u8; 1];
        match (&*r).read(&mut b) {
            Ok(0) => false,
            Err(e) if e.kind() == ErrorKind::WouldBlock => true,
            other => panic!("unexpected read on the inhibitor pipe: {other:?}"),
        }
    }
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(3), "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn locked_hint(v: bool) -> (String, HashMap<String, OwnedVariant>, Vec<String>) {
    let mut changed = HashMap::new();
    changed.insert("LockedHint".to_string(), OwnedVariant::try_from(Variant::from(v)).unwrap());
    ("org.freedesktop.login1.Session".into(), changed, vec![])
}

struct Setup {
    env: Env,
    _buses: (Bus, Bus),
    _daemon: DaemonProc,
    logind: Connection,
    fake: FakeLogind,
    spoofer: Connection,
    screensaver: Connection,
}

fn setup(name: &str, extra_config: &str) -> Option<Setup> {
    if Command::new("dbus-daemon").arg("--version").output().is_err() {
        eprintln!("SKIPPED: dbus-daemon not installed");
        return None;
    }
    let env = Env::new(name);
    env.append_config(extra_config);
    let system = start_bus(&env.root.join("system_bus"))?;
    let session = start_bus(&env.root.join("session_bus"))?;
    // logind is up before any user session: serve the fake before the daemon starts, since
    // the daemon asks for its sleep inhibitor as soon as it connects.
    let logind = connect(&system);
    let fake = FakeLogind::default();
    zbus::block_on(logind.object_server().at(LOGIN_PATH, fake.clone())).unwrap();
    zbus::block_on(logind.request_name("org.freedesktop.login1")).unwrap();
    let daemon = env.spawn_daemon_with(&[
        ("DBUS_SYSTEM_BUS_ADDRESS", &system.addr),
        ("DBUS_SESSION_BUS_ADDRESS", &session.addr),
    ]);
    let spoofer = connect(&system);
    let screensaver = connect(&session);
    Some(Setup { env, _buses: (system, session), _daemon: daemon, logind, fake, spoofer, screensaver })
}

impl Setup {
    fn unlock(&self) {
        let mut c = self.env.connect();
        c.unlock(&self.env.secret(), None, None).unwrap();
        assert!(!c.status().unwrap().locked);
    }

    fn locked(&self) -> bool {
        self.env.connect().status().unwrap().locked
    }

    /// Unlocks, fires `trigger` once, and returns how long until `status` says locked.
    fn time_to_lock(&self, trigger: impl Fn()) -> Option<Duration> {
        self.unlock();
        let t0 = Instant::now();
        trigger();
        while t0.elapsed() < Duration::from_secs(2) {
            if self.locked() {
                return Some(t0.elapsed());
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// The daemon subscribes asynchronously after start: fire until the first lock lands.
    fn warm_up(&self) {
        let t0 = Instant::now();
        loop {
            let hit = self.time_to_lock(|| emit(&self.logind, SESSION_PATH, "org.freedesktop.login1.Session", "Lock", &()));
            if hit.is_some() {
                return;
            }
            assert!(t0.elapsed() < Duration::from_secs(10), "daemon never subscribed: {}", self._daemon.stderr_text());
        }
    }

    fn assert_stays_unlocked(&self, what: &str, trigger: impl Fn()) {
        self.unlock();
        trigger();
        thread::sleep(Duration::from_millis(1200));
        assert!(!self.locked(), "{what} locked the agent");
    }
}

/// Acceptance: after a screen lock or a suspend, `status` reports locked within 1 second.
#[test]
fn every_lock_signal_locks_within_a_second() {
    let Some(s) = setup("dbus-signals", "") else { return };
    assert!(!s._daemon.stderr_text().contains("unavailable"), "{}", s._daemon.stderr_text());
    s.warm_up();

    let session = "org.freedesktop.login1.Session";
    let cases: Vec<(&str, Box<dyn Fn()>)> = vec![
        ("logind Session.Lock", Box::new(|| emit(&s.logind, SESSION_PATH, session, "Lock", &()))),
        ("logind LockedHint=true", Box::new(|| {
            emit(&s.logind, SESSION_PATH, "org.freedesktop.DBus.Properties", "PropertiesChanged", &locked_hint(true))
        })),
        ("logind PrepareForSleep(true)", Box::new(|| {
            emit(&s.logind, LOGIN_PATH, "org.freedesktop.login1.Manager", "PrepareForSleep", &true)
        })),
        ("org.freedesktop.ScreenSaver ActiveChanged(true)", Box::new(|| {
            emit(&s.screensaver, "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver", "ActiveChanged", &true)
        })),
        ("org.gnome.ScreenSaver ActiveChanged(true)", Box::new(|| {
            emit(&s.screensaver, "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver", "ActiveChanged", &true)
        })),
    ];
    for (what, trigger) in cases {
        let t = s.time_to_lock(trigger).unwrap_or_else(|| panic!("{what} did not lock the agent"));
        assert!(t < Duration::from_secs(1), "{what} took {t:?}");
        eprintln!("{what}: locked in {t:?}");
    }
}

#[test]
fn harmless_and_spoofed_signals_do_not_lock() {
    let Some(s) = setup("dbus-negative", "") else { return };
    s.warm_up();
    let session = "org.freedesktop.login1.Session";
    s.assert_stays_unlocked("resume (PrepareForSleep false)", || {
        emit(&s.logind, LOGIN_PATH, "org.freedesktop.login1.Manager", "PrepareForSleep", &false)
    });
    s.assert_stays_unlocked("screensaver deactivating", || {
        emit(&s.screensaver, "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver", "ActiveChanged", &false)
    });
    s.assert_stays_unlocked("LockedHint=false", || {
        emit(&s.logind, SESSION_PATH, "org.freedesktop.DBus.Properties", "PropertiesChanged", &locked_hint(false))
    });
    // Only the owner of org.freedesktop.login1 may lock through logind signals.
    s.assert_stays_unlocked("a spoofed logind Lock", || emit(&s.spoofer, SESSION_PATH, session, "Lock", &()));
    s.assert_stays_unlocked("a logind Lock on the session bus", || {
        emit(&s.screensaver, SESSION_PATH, session, "Lock", &())
    });
}

#[test]
fn config_flags_turn_triggers_off() {
    let Some(s) = setup("dbus-flags", "\n[agent]\nlock_on_suspend = false\n") else { return };
    s.warm_up(); // screen lock still enabled
    s.assert_stays_unlocked("suspend with lock_on_suspend = false", || {
        emit(&s.logind, LOGIN_PATH, "org.freedesktop.login1.Manager", "PrepareForSleep", &true)
    });
    assert!(s.fake.inhibit_calls().is_empty(), "no sleep inhibitor should be taken with lock_on_suspend = false");
}

/// LCK-3 for hibernation: `mlock` does not keep pages out of the hibernation image, so the
/// daemon holds a logind delay inhibitor, releases it right after wiping on
/// `PrepareForSleep(true)` so the sleep can proceed, and takes it again on resume.
#[test]
fn sleep_inhibitor_is_held_until_the_wipe() {
    let Some(s) = setup("dbus-inhibit", "") else { return };
    s.warm_up();
    let sleep = "org.freedesktop.login1.Manager";
    wait_for("the inhibitor to be taken at startup", || !s.fake.inhibit_calls().is_empty());
    let calls = s.fake.inhibit_calls();
    assert_eq!((calls[0].0.as_str(), calls[0].1.as_str(), calls[0].3.as_str()), ("sleep", "age-agent", "delay"));
    assert!(s.fake.held(0), "inhibitor fd released before any suspend");

    let t = s.time_to_lock(|| emit(&s.logind, LOGIN_PATH, sleep, "PrepareForSleep", &true)).expect("suspend did not lock");
    assert!(t < Duration::from_secs(1), "suspend lock took {t:?}");
    wait_for("the inhibitor to be released after the wipe", || !s.fake.held(0));
    assert_eq!(s.fake.inhibit_calls().len(), 1);

    emit(&s.logind, LOGIN_PATH, sleep, "PrepareForSleep", &false);
    wait_for("the inhibitor to be taken again on resume", || s.fake.inhibit_calls().len() >= 2);
    assert!(s.fake.held(1), "inhibitor fd not held after resume");
}

#[test]
fn missing_buses_are_not_fatal() {
    let env = Env::new("dbus-none");
    let mut d = env.spawn_daemon_with(&[
        ("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/system"),
        ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/session"),
    ]);
    thread::sleep(Duration::from_millis(300));
    assert!(d.alive());
    assert!(d.stderr_text().contains("unavailable"));
    let _ = fs::metadata(env.sock()).unwrap();
}
