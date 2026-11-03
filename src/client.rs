//! Client side of the socket protocol, shared by the CLI and the plugin.

use std::io::{self, ErrorKind};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::protocol::{self, ErrorBody, Response, Status, WireStanza};
use crate::{config, sys};

pub const UNLOCK_ATTEMPTS: usize = 3;

pub struct Connection {
    stream: UnixStream,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Agent(ErrorBody),
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Agent(e) => write!(f, "{}", e.message),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl Error {
    pub fn cancelled(message: &str) -> Self {
        Error::Agent(ErrorBody { code: "cancelled".into(), message: message.into() })
    }

    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Agent(e) => Some(&e.code),
            _ => None,
        }
    }
}

impl Connection {
    /// Connects without starting a daemon (`status` must be side-effect free).
    pub fn connect() -> Result<Self, Error> {
        Self::connect_to(config::socket_path()?)
    }

    pub fn connect_to(path: PathBuf) -> Result<Self, Error> {
        let stream = UnixStream::connect(path)?;
        // Mirror of the daemon's check: never talk to a socket owned by someone else.
        if sys::peer_uid(&stream)? != sys::current_uid() {
            return Err(Error::Protocol("socket is served by another user".into()));
        }
        let mut c = Connection { stream };
        match c.call(serde_json::json!({"type": "hello", "version": protocol::VERSION}))? {
            Response::Hello { version, .. } if version == protocol::VERSION => Ok(c),
            other => Err(Error::Protocol(format!("unexpected hello reply {other:?}"))),
        }
    }

    /// DMN-1: connects, starting a detached daemon first when none is running.
    pub fn connect_or_start() -> Result<Self, Error> {
        match Self::connect() {
            Ok(c) => return Ok(c),
            Err(Error::Io(e)) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {}
            Err(e) => return Err(e),
        }
        start_daemon()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match Self::connect() {
                Ok(c) => return Ok(c),
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(e),
            }
        }
    }

    fn call(&mut self, req: serde_json::Value) -> Result<Response, Error> {
        let payload = Zeroizing::new(serde_json::to_vec(&req).map_err(io::Error::other)?);
        protocol::write_frame(&mut self.stream, &payload)?;
        let frame = protocol::read_frame(&mut self.stream)?;
        match serde_json::from_slice(&frame).map_err(|e| Error::Protocol(e.to_string()))? {
            Response::Error { error } => Err(Error::Agent(error)),
            r => Ok(r),
        }
    }

    pub fn status(&mut self) -> Result<Status, Error> {
        match self.call(serde_json::json!({"type": "status"}))? {
            Response::Status(s) => Ok(s),
            r => Err(Error::Protocol(format!("unexpected reply {r:?}"))),
        }
    }

    pub fn lock(&mut self) -> Result<(), Error> {
        self.call(serde_json::json!({"type": "lock"})).map(|_| ())
    }

    pub fn stop(&mut self) -> Result<(), Error> {
        // The daemon may exit before the reply is flushed; that is success.
        match self.call(serde_json::json!({"type": "stop"})) {
            Ok(_) | Err(Error::Io(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// With `epoch`, the agent refuses (`cancelled`) if it was locked or unlocked since.
    pub fn unlock(&mut self, passphrase: &SecretString, timeout_s: Option<u64>, epoch: Option<u64>) -> Result<(), Error> {
        self.call(serde_json::json!({
            "type": "unlock",
            "passphrase": passphrase.expose_secret(),
            "timeout_s": timeout_s,
            "epoch": epoch,
        }))
        .map(|_| ())
    }

    /// Claims the prompt for as long as this connection lives; `Ok(false)` when another
    /// client holds it.
    pub fn claim(&mut self) -> Result<bool, Error> {
        match self.call(serde_json::json!({"type": "claim"})) {
            Ok(_) => Ok(true),
            Err(e) if e.code() == Some("busy") => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Blocks until the lock epoch moves past `epoch` (returns `(true, locked)`), or until
    /// the timeout or, without the claim, until nobody holds it (`(false, locked)`).
    pub fn wait(&mut self, epoch: u64, timeout_s: Option<u64>) -> Result<(bool, bool), Error> {
        match self.call(serde_json::json!({"type": "wait", "epoch": epoch, "timeout_s": timeout_s}))? {
            Response::Waited { changed, locked, .. } => Ok((changed, locked)),
            r => Err(Error::Protocol(format!("unexpected reply {r:?}"))),
        }
    }

    /// A handle that can hang up this connection from another thread, ending a `wait`.
    pub fn hangup_handle(&self) -> io::Result<UnixStream> {
        self.stream.try_clone()
    }

    /// Returns the 16-byte file key for one file's stanzas.
    pub fn unwrap(&mut self, refs: &[String], stanzas: Vec<WireStanza>) -> Result<Zeroizing<Vec<u8>>, Error> {
        match self.call(serde_json::json!({"type": "unwrap", "refs": refs, "stanzas": stanzas}))? {
            Response::FileKey { file_key } => B64
                .decode(file_key.as_bytes())
                .map(Zeroizing::new)
                .map_err(|e| Error::Protocol(e.to_string())),
            r => Err(Error::Protocol(format!("unexpected reply {r:?}"))),
        }
    }

    /// UNL-4: asks for the passphrase up to three times while the agent says it's wrong.
    pub fn unlock_with_prompt(
        &mut self,
        timeout_s: Option<u64>,
        epoch: Option<u64>,
        mut prompt: impl FnMut(Option<&str>) -> io::Result<SecretString>,
    ) -> Result<(), Error> {
        let mut note = None;
        for _ in 0..UNLOCK_ATTEMPTS {
            let pass = prompt(note)?;
            match self.unlock(&pass, timeout_s, epoch) {
                Err(e) if e.code() == Some("bad_passphrase") => note = Some("Wrong passphrase, try again."),
                r => return r,
            }
        }
        Err(Error::Agent(ErrorBody {
            code: "bad_passphrase".into(),
            message: format!("wrong passphrase ({UNLOCK_ATTEMPTS} attempts)"),
        }))
    }
}

/// Starts `age-agent daemon --foreground` detached from the caller's terminal and process group.
pub fn start_daemon() -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = sibling_binary("age-agent")?;
    Command::new(exe)
        .args(["daemon", "--foreground"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map(|_| ())
}

/// The daemon binary is looked up next to the running executable, never via the caller's PATH.
fn sibling_binary(name: &str) -> io::Result<PathBuf> {
    let me = std::env::current_exe()?;
    let path = me.with_file_name(name);
    if path.exists() {
        Ok(path)
    } else {
        Err(io::Error::new(ErrorKind::NotFound, format!("{} not found next to {}", name, me.display())))
    }
}
