//! Shared fixtures: an isolated HOME/XDG tree, an encrypted identity, a fake pinentry.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, iter, thread};

use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, Encryptor, x25519};
use age_agent::client::Connection;
use age_agent::stub;

pub const PASSPHRASE: &str = "correct horse battery staple";
pub const AGE_AGENT: &str = env!("CARGO_BIN_EXE_age-agent");

pub struct Env {
    pub root: PathBuf,
    pub home: PathBuf,
    pub cfg_home: PathBuf,
    pub run: PathBuf,
    /// Fake pinentry fixtures live outside HOME/run so scans for secrets don't see them.
    pub fixtures: PathBuf,
    pub secret_key: String,
    pub recipient: x25519::Recipient,
    pub stub: String,
    pub pass_file: PathBuf,
    pub pinentry_log: PathBuf,
}

impl Env {
    pub fn new(name: &str) -> Env {
        // Not under target/: some sandbox filesystems let connect() succeed on dead socket files.
        let root = std::env::temp_dir().join(format!("age-agent-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (home, run, fixtures) = (root.join("home"), root.join("run"), root.join("fixtures"));
        let cfg_home = home.join(".config");
        for d in [&home, &cfg_home, &run, &fixtures] {
            fs::create_dir_all(d).unwrap();
        }
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();

        let id = x25519::Identity::generate();
        let secret_key = id.to_string().expose_secret().to_owned();
        let recipient = id.to_public();
        let id_file = home.join("identities");
        let e = Encryptor::with_user_passphrase(SecretString::from(PASSPHRASE.to_owned()));
        let mut buf = Vec::new();
        let mut w = e.wrap_output(&mut buf).unwrap();
        w.write_all(format!("{secret_key}\n").as_bytes()).unwrap();
        w.finish().unwrap();
        fs::write(&id_file, buf).unwrap();

        let reference = stub::reference(&recipient.to_string());
        let pass_file = fixtures.join("pass.txt");
        let pinentry_log = fixtures.join("pinentry.log");
        fs::write(&pass_file, PASSPHRASE).unwrap();
        fs::write(fixtures.join("delay"), "0").unwrap();
        let pe = fixtures.join("pinentry");
        fs::write(
            &pe,
            format!(
                "#!/bin/sh\necho 'OK ready'\nwhile read -r l; do case \"$l\" in\n GETPIN) echo getpin >> {log}; sleep \"$(cat {delay})\" </dev/null >/dev/null 2>&1; echo \"D $(cat {pass})\"; echo OK;;\n BYE) echo OK; exit 0;;\n *) echo OK;; esac; done\n",
                log = pinentry_log.display(),
                pass = pass_file.display(),
                delay = fixtures.join("delay").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&pe, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(cfg_home.join("age-agent")).unwrap();
        fs::write(
            cfg_home.join("age-agent/config.toml"),
            format!(
                "[[identity]]\nfile = '{}'\nrefs = ['{}']\n[prompt]\nmode = 'pinentry'\npinentry = '{}'\n",
                id_file.display(),
                stub::ref_hex(&reference),
                pe.display()
            ),
        )
        .unwrap();
        let stub = stub::encode(&reference);
        fs::write(cfg_home.join("age-agent/identities.txt"), format!("# recipient: {recipient}\n{stub}\n")).unwrap();
        Env {
            stub,
            root, home, cfg_home, run, fixtures, secret_key, recipient, pass_file, pinentry_log,
        }
    }

    /// The plugin identity file `setup` would have written.
    pub fn stubs_file(&self) -> PathBuf {
        self.cfg_home.join("age-agent/identities.txt")
    }

    pub fn set_prompt_mode(&self, mode: &str) {
        let p = self.cfg_home.join("age-agent/config.toml");
        let cfg = fs::read_to_string(&p).unwrap();
        let start = cfg.find("mode = '").unwrap();
        let end = start + cfg[start..].find('\n').unwrap();
        fs::write(&p, format!("{}mode = '{mode}'{}", &cfg[..start], &cfg[end..])).unwrap();
    }

    pub fn append_config(&self, toml: &str) {
        let p = self.cfg_home.join("age-agent/config.toml");
        let cfg = fs::read_to_string(&p).unwrap();
        fs::write(&p, cfg + toml).unwrap();
    }

    /// Seconds the fake pinentry waits before answering.
    pub fn set_pinentry_delay(&self, secs: u32) {
        fs::write(self.fixtures.join("delay"), secs.to_string()).unwrap();
    }

    pub fn prompts(&self) -> usize {
        fs::read_to_string(&self.pinentry_log).map(|s| s.lines().count()).unwrap_or(0)
    }

    /// An age client run the way rofi would: no controlling terminal, stdin closed, with
    /// `age-plugin-agent` on PATH.
    pub fn client(&self, args: &[&str]) -> Command {
        let bin_dir = Path::new(AGE_AGENT).parent().unwrap();
        let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap_or_default());
        let mut c = self.command("setsid");
        c.arg("-w").args(args).env("PATH", path).stdin(Stdio::null());
        c
    }

    pub fn sock(&self) -> PathBuf {
        self.run.join("age-agent/agent.sock")
    }

    pub fn command(&self, bin: &str) -> Command {
        let mut c = Command::new(bin);
        c.env("HOME", &self.home).env("XDG_CONFIG_HOME", &self.cfg_home).env("XDG_RUNTIME_DIR", &self.run);
        c
    }

    pub fn spawn_daemon(&self) -> DaemonProc {
        self.spawn_daemon_with(&[])
    }

    pub fn spawn_daemon_with(&self, envs: &[(&str, &str)]) -> DaemonProc {
        let stderr = self.root.join("daemon.stderr");
        let child = self
            .command(AGE_AGENT)
            .args(["daemon", "--foreground"])
            .envs(envs.iter().copied())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let d = DaemonProc { child, stderr };
        let t0 = Instant::now();
        while Connection::connect_to(self.sock()).is_err() {
            assert!(t0.elapsed() < Duration::from_secs(5), "daemon did not come up: {}", d.stderr_text());
            thread::sleep(Duration::from_millis(50));
        }
        d
    }

    pub fn connect(&self) -> Connection {
        Connection::connect_to(self.sock()).unwrap()
    }

    pub fn secret(&self) -> SecretString {
        SecretString::from(PASSPHRASE.to_owned())
    }

    pub fn ciphertext(&self, msg: &[u8]) -> Vec<u8> {
        let e = Encryptor::with_recipients(iter::once(&self.recipient as &dyn age::Recipient)).unwrap();
        let mut buf = Vec::new();
        let mut w = e.wrap_output(&mut buf).unwrap();
        w.write_all(msg).unwrap();
        w.finish().unwrap();
        buf
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Daemons auto-started by clients are not children of the test; stop them here.
        if let Ok(mut c) = Connection::connect_to(self.sock()) {
            let _ = c.stop();
        }
        if !thread::panicking() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

pub struct DaemonProc {
    pub child: Child,
    pub stderr: PathBuf,
}

impl DaemonProc {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn stderr_text(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    pub fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }
}

impl Drop for DaemonProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Decrypts through the real plugin; needs PATH and XDG_* set in this process.
pub fn decrypt_via_plugin(stub_str: &str, ct: &[u8]) -> Result<Vec<u8>, String> {
    let ident: age::plugin::Identity = stub_str.parse().unwrap();
    let plugin = age::plugin::IdentityPluginV1::new("agent", &[ident], age::NoCallbacks).map_err(|e| e.to_string())?;
    let d = Decryptor::new(ct).map_err(|e| e.to_string())?;
    let mut r = d.decrypt(iter::once(&plugin as &dyn age::Identity)).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    r.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&p, f),
            Ok(t) if t.is_file() => f(&p),
            _ => {}
        }
    }
}
