//! The age plugin side (`age-plugin-agent`): forwards stanzas to the daemon.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::Shutdown;
use std::sync::Arc;
use std::thread;

use age_core::format::{FileKey, Stanza};
use age_plugin::identity::{Error, IdentityPluginV1};
use age_plugin::{Callbacks, PluginHandler};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use secrecy::SecretString;

use crate::client::{self, Connection};
use crate::config::Config;
use crate::protocol::WireStanza;
use crate::{prompt, stub};

/// Stanza types the daemon can unwrap. Anything else is ignored, as the plugin spec requires.
const SUPPORTED: &[&str] = &["X25519"];

pub struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = Infallible;
    type IdentityV1 = Plugin;

    fn identity_v1(self) -> io::Result<Plugin> {
        Ok(Plugin { refs: Vec::new(), conn: None })
    }
}

pub struct Plugin {
    refs: Vec<String>,
    conn: Option<Connection>,
}

impl IdentityPluginV1 for Plugin {
    fn add_identity(&mut self, index: usize, _plugin_name: &str, bytes: &[u8]) -> Result<(), Error> {
        let r = stub::decode_payload(bytes).map_err(|message| Error::Identity { index, message })?;
        self.refs.push(stub::ref_hex(&r));
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<Error>>>> {
        let mut results = HashMap::new();
        if self.refs.is_empty() {
            return Ok(results);
        }
        for (file_index, stanzas) in files.into_iter().enumerate() {
            let wire: Vec<_> = stanzas
                .iter()
                .filter(|s| SUPPORTED.contains(&s.tag.as_str()))
                .map(|s| WireStanza { kind: s.tag.clone(), args: s.args.clone(), body: B64.encode(&s.body) })
                .collect();
            if wire.is_empty() {
                continue;
            }
            match self.unwrap_one(&wire, &mut callbacks) {
                Ok(key) => {
                    results.insert(file_index, Ok(key));
                }
                Err(client::Error::Agent(e)) if e.code == "no_match" => {}
                Err(client::Error::Agent(e)) if e.code == "malformed" => {
                    let err = Error::Stanza { file_index, stanza_index: 0, message: e.message };
                    results.insert(file_index, Err(vec![err]));
                }
                Err(e) => {
                    let err = Error::Internal { message: format!("age-agent: {e}") };
                    results.insert(file_index, Err(vec![err]));
                }
            }
        }
        Ok(results)
    }
}

impl Plugin {
    fn unwrap_one(
        &mut self,
        wire: &[WireStanza],
        callbacks: &mut impl Callbacks<Error>,
    ) -> Result<FileKey, client::Error> {
        let conn = match &mut self.conn {
            Some(c) => c,
            slot => slot.insert(Connection::connect_or_start()?),
        };
        let key = match conn.unwrap(&self.refs, wire.to_vec()) {
            Err(e) if e.code() == Some("locked") => {
                ensure_unlocked(conn, callbacks)?;
                conn.unwrap(&self.refs, wire.to_vec())?
            }
            r => r?,
        };
        let bytes: [u8; 16] = key[..].try_into().map_err(|_| client::Error::Protocol("file key is not 16 bytes".into()))?;
        Ok(FileKey::init_with_mut(|k| k.copy_from_slice(&bytes)))
    }
}

/// Gets the agent unlocked, prompting at most once across concurrent clients.
fn ensure_unlocked(conn: &mut Connection, callbacks: &mut impl Callbacks<Error>) -> Result<(), client::Error> {
    let cfg = Config::load().unwrap_or_default();
    loop {
        let st = conn.status()?;
        if !st.locked {
            return Ok(());
        }
        // The claim is held by this second connection until it closes.
        let mut watcher = Connection::connect()?;
        if !watcher.claim()? {
            // Another client is prompting: queue behind it instead of a second prompt.
            match conn.wait(st.epoch, None)? {
                (true, true) => return Err(client::Error::cancelled("unlock cancelled by `age-agent lock`")),
                _ => continue, // unlocked, or that prompt gave up: look again
            }
        }
        return prompt_and_unlock(conn, watcher, &cfg, callbacks, st.epoch);
    }
}

/// LCK-1: the watcher (holding the claim) cancels the prompt on any lock or unlock, and the
/// unlock itself is bound to the epoch the prompt started in.
fn prompt_and_unlock(
    conn: &mut Connection,
    mut watcher: Connection,
    cfg: &Config,
    callbacks: &mut impl Callbacks<Error>,
    epoch: u64,
) -> Result<(), client::Error> {
    let cancel = Arc::new(prompt::Cancel::default());
    let hangup = watcher.hangup_handle()?;
    let c = cancel.clone();
    let watch = thread::spawn(move || {
        // Each `wait` lasts at most MAX_WAIT; keep watching until the epoch moves or the
        // prompt below ends (then `hangup` closes this connection and `wait` errors out).
        loop {
            match watcher.wait(epoch, None) {
                Ok((true, _)) => return c.cancel(),
                Ok((false, _)) => continue,
                Err(_) => return,
            }
        }
    });
    let result = conn.unlock_with_prompt(None, Some(epoch), |note| ask_passphrase(cfg, callbacks, note, &cancel));
    let _ = hangup.shutdown(Shutdown::Both);
    let _ = watch.join();
    match result {
        Err(e) if cancel.is_cancelled() || e.code() == Some("cancelled") => {
            // Someone else unlocked meanwhile: fine. Otherwise it was an explicit lock.
            match conn.status()?.locked {
                false => Ok(()),
                true => Err(client::Error::cancelled("unlock cancelled by `age-agent lock`")),
            }
        }
        r => r,
    }
}

/// UNL-2: age's `request-secret` first. age and rage fail it at once when there is no
/// terminal (checked in M1), so a client without one (rofi) falls through to pinentry.
fn ask_passphrase(
    cfg: &Config,
    callbacks: &mut impl Callbacks<Error>,
    note: Option<&str>,
    cancel: &prompt::Cancel,
) -> io::Result<SecretString> {
    let message = match note {
        Some(n) => format!("{n}\nUnlock age-agent"),
        None => "Unlock age-agent".to_string(),
    };
    if cfg.prompt.mode != "pinentry" {
        match callbacks.request_secret(&message) {
            Ok(Ok(s)) => {
                cancel.check()?; // the answer may arrive after a lock; discard it
                return Ok(s);
            }
            _ if cfg.prompt.mode != "terminal" => {}
            Ok(Err(e)) => return Err(io::Error::other(format!("passphrase request failed: {e:?}"))),
            Err(e) => return Err(e),
        }
    }
    prompt::pinentry(&prompt::pinentry_path(&cfg.prompt)?, &message, cancel)
}
