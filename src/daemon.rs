//! The long-running daemon: holds unlocked identities and unwraps stanzas on request.

use std::io::{self, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use std::{fs, thread};

use age::Identity;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::config::{self, Config};
use crate::identities::{self, LoadError, Loaded};
use crate::protocol::{self, Request, Response, Status};
use crate::{stub, sys};

const TICK: Duration = Duration::from_millis(250);
const CONN_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// Unlocked identities plus the clocks that decide when they are wiped (LCK-2).
pub struct Session {
    identities: Vec<Loaded>,
    unlocked_at: Instant,
    last_used: Instant,
    idle: Duration,
    max_lifetime: Duration,
    locked: Option<sys::LockedRegion>,
}

impl Session {
    /// `identities` is locked in place and never reallocated: growing or shrinking it would
    /// move the keys and leave an unzeroized copy outside the locked region.
    pub fn new(identities: Vec<Loaded>, now: Instant, idle: Duration, max_lifetime: Duration) -> Self {
        let locked = sys::LockedRegion::new(&identities);
        if locked.is_none() && !identities.is_empty() {
            eprintln!("age-agent: warning: could not lock memory (raise RLIMIT_MEMLOCK); secrets may reach swap");
        }
        Self { identities, unlocked_at: now, last_used: now, idle, max_lifetime, locked }
    }

    /// Time left before the idle timeout; `None` when there is none.
    pub fn idle_left(&self, now: Instant) -> Option<Duration> {
        (!self.idle.is_zero()).then(|| self.idle.saturating_sub(now.duration_since(self.last_used)))
    }

    pub fn lifetime_left(&self, now: Instant) -> Option<Duration> {
        (!self.max_lifetime.is_zero())
            .then(|| self.max_lifetime.saturating_sub(now.duration_since(self.unlocked_at)))
    }

    pub fn memory_locked(&self) -> bool {
        self.locked.is_some()
    }

    pub fn expired(&self, now: Instant) -> bool {
        self.idle_left(now) == Some(Duration::ZERO) || self.lifetime_left(now) == Some(Duration::ZERO)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Zeroize first (each identity wipes itself on drop); the page lock is released after.
        self.identities.clear();
        self.locked = None;
    }
}

/// Everything guarded by the daemon's one state lock.
pub struct Inner {
    session: Option<Session>,
    /// Bumped on every lock and unlock; waiters and epoch-bound unlocks key off it.
    epoch: u64,
    /// Whether some connection holds the prompt claim.
    prompting: bool,
}

pub struct Daemon {
    state: Mutex<Inner>,
    changed: Condvar,
    /// Serializes unlocks so concurrent clients don't run scrypt in parallel.
    unlock_gate: Mutex<()>,
    load_config: fn() -> io::Result<Config>,
    socket: PathBuf,
}

impl Daemon {
    pub fn new(socket: PathBuf, load_config: fn() -> io::Result<Config>) -> Self {
        let inner = Inner { session: None, epoch: 0, prompting: false };
        Self { state: Mutex::new(inner), changed: Condvar::new(), unlock_gate: Mutex::new(()), load_config, socket }
    }

    fn state(&self) -> MutexGuard<'_, Inner> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_session(&self, inner: &mut Inner, session: Option<Session>) {
        inner.session = session; // dropping the old session zeroizes it
        inner.epoch += 1;
        self.changed.notify_all();
    }

    /// LCK-1: wipes every identity and, through the epoch, cancels pending prompts. Locking
    /// an already locked agent still bumps the epoch, so `lock` always cancels prompts.
    pub fn lock(&self) {
        let mut inner = self.state();
        self.set_session(&mut inner, None);
    }

    pub fn expire_if_due(&self, now: Instant) {
        let mut inner = self.state();
        if inner.session.as_ref().is_some_and(|s| s.expired(now)) {
            self.set_session(&mut inner, None);
        }
    }

    fn claim(&self) -> bool {
        let mut inner = self.state();
        !std::mem::replace(&mut inner.prompting, true)
    }

    fn release_claim(&self) {
        self.state().prompting = false;
        self.changed.notify_all();
    }

    /// Blocks until the epoch moves past `epoch`, the timeout, or the peer hangs up (`None`).
    /// Without the claim, it also returns once nobody holds it.
    fn wait(&self, stream: &UnixStream, epoch: u64, claimed: bool, timeout: Duration) -> Option<Response> {
        let deadline = Instant::now() + timeout.min(protocol::MAX_WAIT);
        let mut inner = self.state();
        let changed = loop {
            if inner.epoch != epoch {
                break true;
            }
            let now = Instant::now();
            if now >= deadline || (!claimed && !inner.prompting) {
                break false;
            }
            let slice = (deadline - now).min(Duration::from_millis(500));
            inner = self.changed.wait_timeout(inner, slice).unwrap_or_else(|e| e.into_inner()).0;
            if sys::peer_hung_up(stream) {
                return None;
            }
        };
        Some(Response::Waited { changed, locked: inner.session.is_none(), epoch: inner.epoch })
    }

    pub fn handle(&self, req: Request) -> Response {
        match req {
            Request::Hello { .. } | Request::Wait { .. } | Request::Claim => unreachable!("handled per connection"),
            Request::Status => Response::Status(self.status(Instant::now())),
            Request::Lock => {
                self.lock();
                Response::ok()
            }
            Request::Stop => {
                self.lock();
                // Exit after the reply has had time to flush.
                let socket = self.socket.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(100));
                    let _ = fs::remove_file(socket);
                    std::process::exit(0);
                });
                Response::ok()
            }
            Request::Unlock { passphrase, timeout_s, epoch } => self.unlock(&passphrase, timeout_s, epoch),
            Request::Unwrap { refs, stanzas } => self.unwrap(&refs, &stanzas),
        }
    }

    pub fn status(&self, now: Instant) -> Status {
        self.expire_if_due(now);
        let inner = self.state();
        let (epoch, prompting) = (inner.epoch, inner.prompting);
        match inner.session.as_ref() {
            None => Status {
                locked: true,
                recipients: vec![],
                idle_left_s: None,
                lifetime_left_s: None,
                epoch,
                prompting,
                memory_locked: false,
            },
            Some(s) => Status {
                locked: false,
                recipients: s.identities.iter().map(|i| i.recipient.clone()).collect(),
                idle_left_s: s.idle_left(now).map(|d| d.as_secs()),
                lifetime_left_s: s.lifetime_left(now).map(|d| d.as_secs()),
                epoch,
                prompting,
                memory_locked: s.memory_locked(),
            },
        }
    }

    fn unlock(&self, passphrase: &SecretString, timeout_s: Option<u64>, epoch: Option<u64>) -> Response {
        let _gate = self.unlock_gate.lock().unwrap_or_else(|e| e.into_inner());
        let cfg = match (self.load_config)() {
            Ok(c) => c,
            Err(e) => return Response::error("internal", format!("config: {e}")),
        };
        if cfg.identities.is_empty() {
            return Response::error("no_identities", "no identity files configured; run `age-agent setup`");
        }
        let (idle, max) = match (cfg.idle_timeout(), cfg.max_lifetime()) {
            (Ok(i), Ok(m)) => (timeout_s.map_or(i, Duration::from_secs), m),
            (Err(e), _) | (_, Err(e)) => return Response::error("internal", format!("config: {e}")),
        };
        let mut paths = Vec::with_capacity(cfg.identities.len());
        for entry in &cfg.identities {
            match config::expand_tilde(&entry.file) {
                Ok(p) => paths.push(p),
                Err(e) => return Response::error("internal", e.to_string()),
            }
        }
        // One exactly-sized allocation for every file (plain files ignore the passphrase).
        let all = match identities::load_all(&paths, Some(passphrase)) {
            Ok(all) => all,
            Err(LoadError::BadPassphrase) => return Response::error("bad_passphrase", "wrong passphrase"),
            Err(e) => return Response::error("internal", e.to_string()),
        };
        if all.is_empty() {
            return Response::error("no_identities", "the configured identity files hold no identities");
        }
        let mut inner = self.state();
        // Checked after the scrypt work, so a lock during either the prompt or the
        // decryption cancels this unlock.
        if epoch.is_some_and(|e| e != inner.epoch) {
            return Response::error("cancelled", "the agent was locked or unlocked while prompting");
        }
        self.set_session(&mut inner, Some(Session::new(all, Instant::now(), idle, max)));
        Response::ok()
    }

    fn unwrap(&self, refs: &[String], stanzas: &[protocol::WireStanza]) -> Response {
        let wanted: Vec<_> = refs.iter().filter_map(|r| stub::ref_from_hex(r)).collect();
        let mut parsed = Vec::with_capacity(stanzas.len());
        for s in stanzas {
            match B64.decode(&s.body) {
                Ok(body) => parsed.push(age_core::format::Stanza { tag: s.kind.clone(), args: s.args.clone(), body }),
                Err(_) => return Response::error("malformed", "stanza body is not base64"),
            }
        }
        let now = Instant::now();
        self.expire_if_due(now);
        let mut inner = self.state();
        let Some(session) = inner.session.as_mut() else {
            return Response::error("locked", "the agent is locked");
        };
        // DEC-2: only identities named by the caller's stubs are tried.
        for loaded in session.identities.iter().filter(|i| wanted.contains(&i.reference)) {
            match loaded.identity.unwrap_stanzas(&parsed) {
                None => {}
                Some(Ok(key)) => {
                    session.last_used = now;
                    let key = Zeroizing::new(B64.encode(key.expose_secret()));
                    return Response::FileKey { file_key: key };
                }
                Some(Err(e)) => return Response::error("malformed", e.to_string()),
            }
        }
        Response::error("no_match", "no loaded identity unwraps these stanzas")
    }

    /// LCK-4: wipe, remove the socket, exit.
    fn shutdown(&self) -> ! {
        self.lock();
        let _ = fs::remove_file(&self.socket);
        std::process::exit(0);
    }

    fn serve_conn(&self, mut stream: UnixStream) -> io::Result<()> {
        // SEC-4: peer UID check on every connection.
        if sys::peer_uid(&stream)? != sys::current_uid() {
            return Ok(());
        }
        stream.set_read_timeout(Some(CONN_READ_TIMEOUT))?;
        let mut claimed = false;
        let result = self.serve_requests(&mut stream, &mut claimed);
        if claimed {
            self.release_claim();
        }
        result
    }

    fn serve_requests(&self, stream: &mut UnixStream, claimed: &mut bool) -> io::Result<()> {
        let mut greeted = false;
        loop {
            let frame = match protocol::read_frame(stream) {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            let resp = match protocol::parse_request(&frame) {
                Err(e) => Response::error("bad_request", e),
                Ok(Request::Hello { version }) if version == protocol::VERSION => {
                    greeted = true;
                    Response::Hello { version, daemon_version: env!("CARGO_PKG_VERSION").into() }
                }
                Ok(Request::Hello { version }) => {
                    Response::error("version", format!("unsupported protocol version {version}"))
                }
                Ok(_) if !greeted => Response::error("bad_request", "expected hello first"),
                Ok(Request::Claim) if *claimed => Response::ok(),
                Ok(Request::Claim) => match self.claim() {
                    true => {
                        *claimed = true;
                        Response::ok()
                    }
                    false => Response::error("busy", "another client is already prompting"),
                },
                Ok(Request::Wait { epoch, timeout_s }) => {
                    let timeout = timeout_s.map_or(protocol::MAX_WAIT, Duration::from_secs);
                    match self.wait(stream, epoch, *claimed, timeout) {
                        Some(r) => r,
                        None => return Ok(()),
                    }
                }
                Ok(req) => self.handle(req),
            };
            drop(frame);
            let out = Zeroizing::new(serde_json::to_vec(&resp).map_err(io::Error::other)?);
            protocol::write_frame(stream, &out)?;
        }
    }
}

/// Binds the socket, refusing to start when a live daemon holds it (DMN-2) and checking
/// the parent directory is ours and private (SEC-4).
fn bind(socket: &Path) -> io::Result<UnixListener> {
    let dir = socket.parent().expect("socket path has a parent");
    if !dir.exists() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != sys::current_uid() || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} must be a directory owned by you with mode 0700", dir.display()),
        ));
    }
    match UnixListener::bind(socket) {
        Ok(l) => Ok(l),
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            if UnixStream::connect(socket).is_ok() {
                return Err(io::Error::new(ErrorKind::AddrInUse, "age-agent is already running"));
            }
            fs::remove_file(socket)?;
            UnixListener::bind(socket)
        }
        Err(e) => Err(e),
    }
}

/// Runs the daemon in this process until stopped.
pub fn run(socket: PathBuf, load_config: fn() -> io::Result<Config>) -> io::Result<()> {
    // Harden before the socket exists, so no client can ever talk to a dumpable daemon.
    sys::harden_process();
    let listener = bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let daemon = Arc::new(Daemon::new(socket, load_config));

    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ])?;
    let d = daemon.clone();
    thread::spawn(move || {
        for sig in signals.forever() {
            if sig != signal_hook::consts::SIGHUP {
                d.shutdown();
            }
        }
    });
    match load_config() {
        Ok(cfg) => crate::autolock::spawn(daemon.clone(), cfg.agent.lock_on_screen_lock, cfg.agent.lock_on_suspend),
        Err(e) => eprintln!("age-agent: auto-lock disabled, bad config: {e}"),
    }
    let d = daemon.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(TICK);
            d.expire_if_due(Instant::now());
        }
    });

    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let d = daemon.clone();
        thread::spawn(move || {
            let _ = d.serve_conn(conn);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(idle: u64, max: u64, now: Instant) -> Session {
        Session::new(vec![], now, Duration::from_secs(idle), Duration::from_secs(max))
    }

    #[test]
    fn idle_timeout_on_mocked_clock() {
        let t0 = Instant::now();
        let s = session(900, 28800, t0);
        assert!(!s.expired(t0 + Duration::from_secs(899)));
        assert_eq!(s.idle_left(t0 + Duration::from_secs(100)), Some(Duration::from_secs(800)));
        assert!(s.expired(t0 + Duration::from_secs(900)));
    }

    #[test]
    fn max_lifetime_beats_activity() {
        let t0 = Instant::now();
        let mut s = session(900, 3600, t0);
        s.last_used = t0 + Duration::from_secs(3590);
        assert!(!s.expired(t0 + Duration::from_secs(3599)));
        assert!(s.expired(t0 + Duration::from_secs(3600)));
    }

    #[test]
    fn zero_means_none() {
        let t0 = Instant::now();
        let s = session(0, 0, t0);
        assert_eq!(s.idle_left(t0), None);
        assert!(!s.expired(t0 + Duration::from_secs(10_000_000)));
    }
}
