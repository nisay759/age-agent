//! End to end on Linux: real daemon, real `age-plugin-agent`, driven by the `age` crate's
//! plugin client, with a fake pinentry.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use std::{env, fs, iter, thread};

use age::secrecy::SecretString;
use age::{Decryptor, Encryptor, x25519};
use age_agent::client::Connection;
use age_agent::stub;

fn decrypt_via_plugin(stub_str: &str, ct: &[u8]) -> Result<Vec<u8>, String> {
    let ident: age::plugin::Identity = stub_str.parse().unwrap();
    let plugin = age::plugin::IdentityPluginV1::new("agent", &[ident], age::NoCallbacks).map_err(|e| e.to_string())?;
    let d = Decryptor::new(ct).map_err(|e| e.to_string())?;
    let mut r = d.decrypt(iter::once(&plugin as &dyn age::Identity)).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    r.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn count(p: &Path) -> usize {
    fs::read_to_string(p).map(|s| s.lines().count()).unwrap_or(0)
}

#[test]
fn full_session() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("e2e-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let (home, cfg_dir, run) = (root.join("home"), root.join("home/.config"), root.join("run"));
    for d in [&home, &cfg_dir, &run] {
        fs::create_dir_all(d).unwrap();
    }
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();

    let bin_dir = Path::new(env!("CARGO_BIN_EXE_age-agent")).parent().unwrap().to_owned();
    // SAFETY: this is the only test in the binary, so nothing else reads the environment concurrently.
    unsafe {
        env::set_var("HOME", &home);
        env::set_var("XDG_CONFIG_HOME", &cfg_dir);
        env::set_var("XDG_RUNTIME_DIR", &run);
        env::set_var("PATH", format!("{}:{}", bin_dir.display(), env::var("PATH").unwrap()));
    }

    // At-rest identity, encrypted with a passphrase.
    let id = x25519::Identity::generate();
    let recipient = id.to_public();
    let text = format!("{}\n", age::secrecy::ExposeSecret::expose_secret(&id.to_string()));
    let id_file = home.join("identities");
    {
        let e = Encryptor::with_user_passphrase(SecretString::from("hunter2".to_owned()));
        let mut buf = Vec::new();
        let mut w = e.wrap_output(&mut buf).unwrap();
        w.write_all(text.as_bytes()).unwrap();
        w.finish().unwrap();
        fs::write(&id_file, buf).unwrap();
    }
    let reference = stub::reference(&recipient.to_string());
    let stub_str = stub::encode(&reference);

    // Fake pinentry: answers with the contents of pass.txt and logs each GETPIN.
    let pass = root.join("pass.txt");
    let log = root.join("pinentry.log");
    fs::write(&pass, "hunter2").unwrap();
    let pe = root.join("pinentry");
    fs::write(
        &pe,
        format!(
            "#!/bin/sh\necho 'OK ready'\nwhile read -r l; do case \"$l\" in\n GETPIN) echo getpin >> {log}; echo \"D $(cat {pass})\"; echo OK;;\n BYE) echo OK; exit 0;;\n *) echo OK;; esac; done\n",
            log = log.display(),
            pass = pass.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&pe, fs::Permissions::from_mode(0o755)).unwrap();

    fs::create_dir_all(cfg_dir.join("age-agent")).unwrap();
    fs::write(
        cfg_dir.join("age-agent/config.toml"),
        format!(
            "[[identity]]\nfile = '{}'\nrefs = ['{}']\n[prompt]\nmode = 'pinentry'\npinentry = '{}'\n",
            id_file.display(),
            stub::ref_hex(&reference),
            pe.display()
        ),
    )
    .unwrap();

    let ct = {
        let e = Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient)).unwrap();
        let mut buf = Vec::new();
        let mut w = e.wrap_output(&mut buf).unwrap();
        w.write_all(b"the secret").unwrap();
        w.finish().unwrap();
        buf
    };

    // No daemon: status must not start one.
    assert!(Connection::connect().is_err());
    assert!(!run.join("age-agent/agent.sock").exists());

    // First decryption auto-starts the daemon and prompts once.
    assert_eq!(decrypt_via_plugin(&stub_str, &ct).unwrap(), b"the secret");
    assert_eq!(count(&log), 1);
    let mut c = Connection::connect().unwrap();
    let st = c.status().unwrap();
    assert!(!st.locked);
    assert_eq!(st.recipients, [recipient.to_string()]);
    assert!(st.idle_left_s.unwrap() <= 900 && st.lifetime_left_s.unwrap() <= 28800);

    // Later decryptions don't prompt.
    for _ in 0..10 {
        assert_eq!(decrypt_via_plugin(&stub_str, &ct).unwrap(), b"the secret");
    }
    assert_eq!(count(&log), 1);

    // DEC-2: a stub naming some other identity gets nothing.
    let other = stub::encode(&stub::reference("age1other"));
    assert!(decrypt_via_plugin(&other, &ct).is_err());

    // Lock wipes immediately and the next decryption prompts again.
    c.lock().unwrap();
    assert!(c.status().unwrap().locked);
    assert_eq!(decrypt_via_plugin(&stub_str, &ct).unwrap(), b"the secret");
    assert_eq!(count(&log), 2);

    // UNL-4: a wrong passphrase gets 3 attempts, then a clear error.
    c.lock().unwrap();
    fs::write(&pass, "wrong").unwrap();
    assert!(decrypt_via_plugin(&stub_str, &ct).is_err());
    assert_eq!(count(&log), 5);
    assert!(c.status().unwrap().locked);
    fs::write(&pass, "hunter2").unwrap();

    // Socket-level unlock with a per-unlock idle timeout (UNL-3, LCK-2).
    c.unlock(&SecretString::from("hunter2".to_owned()), Some(1), None).unwrap();
    assert!(!c.status().unwrap().locked);
    let t0 = Instant::now();
    while !c.status().unwrap().locked {
        assert!(t0.elapsed() < Duration::from_secs(4), "idle timeout never fired");
        thread::sleep(Duration::from_millis(100));
    }

    // Protocol hygiene: a connection must say hello first; DMN-2: a second daemon refuses.
    let out = Command::new(env!("CARGO_BIN_EXE_age-agent")).args(["daemon", "--foreground"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("already running"), "{out:?}");

    // Stop removes the socket.
    c.stop().unwrap();
    let t0 = Instant::now();
    while run.join("age-agent/agent.sock").exists() {
        assert!(t0.elapsed() < Duration::from_secs(3));
        thread::sleep(Duration::from_millis(50));
    }
}
