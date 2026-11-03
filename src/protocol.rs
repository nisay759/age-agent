//! Socket protocol, version 1 (SEC-6): 4-byte big-endian length, then one JSON object.

use std::io::{self, Read, Write};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const VERSION: u32 = 1;
pub const MAX_MESSAGE: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    Hello { version: u32 },
    Status,
    /// `epoch`, when given, makes the unlock fail with `cancelled` if the agent was locked or
    /// unlocked since the caller read that epoch (LCK-1: a lock cancels a pending prompt).
    Unlock { passphrase: SecretString, timeout_s: Option<u64>, epoch: Option<u64> },
    Lock,
    Stop,
    Unwrap { refs: Vec<String>, stanzas: Vec<WireStanza> },
    /// Atomically claims the right to show the unlock prompt: `ok`, or error `busy` when
    /// another connection holds it. Held until this connection closes.
    Claim,
    /// Blocks until the lock epoch differs from `epoch` (any lock or unlock) or the timeout.
    /// On a connection without the claim, it also returns once nobody holds it.
    Wait { epoch: u64, timeout_s: Option<u64> },
}

/// Upper bound for `wait`, so an abandoned waiter cannot pin a daemon thread forever.
pub const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WireStanza {
    #[serde(rename = "type")]
    pub kind: String,
    pub args: Vec<String>,
    /// base64
    pub body: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum Response {
    Error { error: ErrorBody },
    Hello { version: u32, daemon_version: String },
    Status(Status),
    Waited { changed: bool, locked: bool, epoch: u64 },
    FileKey { file_key: Zeroizing<String> },
    Ok { ok: bool },
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Status {
    pub locked: bool,
    pub recipients: Vec<String>,
    pub idle_left_s: Option<u64>,
    pub lifetime_left_s: Option<u64>,
    /// Bumped on every lock and unlock.
    #[serde(default)]
    pub epoch: u64,
    /// True while some client shows an unlock prompt.
    #[serde(default)]
    pub prompting: bool,
    /// Whether the identities sit in mlocked memory. False when locked, and when the
    /// daemon could not lock memory (then they may reach swap).
    #[serde(default)]
    pub memory_locked: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl Response {
    pub fn ok() -> Self {
        Response::Ok { ok: true }
    }

    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Response::Error { error: ErrorBody { code: code.into(), message: message.into() } }
    }
}

/// Reads one frame. The buffer is zeroized on drop because it may hold a passphrase.
pub fn read_frame(r: &mut impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut len = [0; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut buf = Zeroizing::new(vec![0; len]);
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "message too large"));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    w.write_all(&frame)?;
    w.flush()
}

pub fn parse_request(frame: &[u8]) -> Result<Request, String> {
    let req: Request = serde_json::from_slice(frame).map_err(|e| e.to_string())?;
    // serde's `deny_unknown_fields` is ignored for unit variants of internally tagged enums.
    if matches!(req, Request::Status | Request::Lock | Request::Stop) {
        let v: serde_json::Value = serde_json::from_slice(frame).map_err(|e| e.to_string())?;
        if v.as_object().is_none_or(|o| o.len() != 1) {
            return Err("unexpected fields".into());
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"type\":\"lock\"}").unwrap();
        assert_eq!(&buf[..4], &[0, 0, 0, 15]);
        let got = read_frame(&mut buf.as_slice()).unwrap();
        assert!(matches!(parse_request(&got), Ok(Request::Lock)));
    }

    #[test]
    fn oversize_frame_rejected() {
        let len = (MAX_MESSAGE as u32 + 1).to_be_bytes();
        assert!(read_frame(&mut len.as_slice()).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![0; MAX_MESSAGE + 1]).is_err());
    }

    #[test]
    fn truncated_frame_rejected() {
        assert!(read_frame(&mut [0, 0, 0, 9, b'{'].as_slice()).is_err());
    }

    #[test]
    fn strict_parsing() {
        assert!(parse_request(b"{\"type\":\"nope\"}").is_err());
        assert!(parse_request(b"{\"type\":\"lock\",\"extra\":1}").is_err());
        assert!(parse_request(b"not json").is_err());
        assert!(parse_request(b"{\"type\":\"hello\",\"version\":1}").is_ok());
        assert!(parse_request(b"{\"type\":\"unlock\",\"passphrase\":\"x\"}").is_ok());
    }

    #[test]
    fn response_shapes() {
        let e = serde_json::to_string(&Response::error("locked", "m")).unwrap();
        assert_eq!(e, r#"{"error":{"code":"locked","message":"m"}}"#);
        let back: Response = serde_json::from_str(&e).unwrap();
        assert_eq!(back, Response::error("locked", "m"));
        let ok: Response = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert_eq!(ok, Response::ok());
    }
}
