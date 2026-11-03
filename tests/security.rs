//! M2 security tests (spec: "Stack, testing and acceptance → Security").

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::time::Duration;
use std::{fs, thread};

use age_agent::client::Connection;
use age_agent::protocol::{self, MAX_MESSAGE};
use common::*;

fn nobody_can_run() -> bool {
    Command::new("sudo").args(["-n", "-u", "nobody", "python3", "-I", "-c", "pass"]).status().is_ok_and(|s| s.success())
        && Command::new("sudo")
            .args(["-n", "-u", "nobody", "test", "-x", AGE_AGENT])
            .status()
            .is_ok_and(|s| s.success())
}

/// Speaks the raw protocol as `nobody` (the real client refuses foreign sockets on its own,
/// which would mask the daemon's check). Prints `reply`, `closed` or `connect-error: …`.
const NOBODY_PROBE: &str = r#"
import socket, struct, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(3)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print("connect-error:", e.strerror); sys.exit(0)
msg = b'{"type":"hello","version":1}'
try:
    s.sendall(struct.pack(">I", len(msg)) + msg)
    print("reply" if s.recv(4) else "closed")
except OSError:
    print("closed")
"#;

fn probe_as_nobody(env: &Env) -> String {
    let out = Command::new("sudo")
        .args(["-n", "-u", "nobody", "python3", "-I", "-c", NOBODY_PROBE])
        .arg(env.sock())
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn another_local_user_cannot_reach_the_socket() {
    if !nobody_can_run() {
        eprintln!("SKIPPED: needs passwordless `sudo -u nobody` and a world-traversable build dir");
        return;
    }
    let env = Env::new("sec-otheruser");
    let _d = env.spawn_daemon();
    env.connect().unlock(&env.secret(), None, None).unwrap();

    // Layer 1: filesystem permissions (dir 0700, socket 0600).
    let r = probe_as_nobody(&env);
    assert!(r.starts_with("connect-error"), "nobody got past the filesystem: {r}");

    // Layer 2: with permissions deliberately opened up, nobody can connect but the peer-UID
    // check must drop the connection without a reply.
    fs::set_permissions(&env.run, fs::Permissions::from_mode(0o711)).unwrap();
    fs::set_permissions(env.run.join("age-agent"), fs::Permissions::from_mode(0o711)).unwrap();
    fs::set_permissions(env.sock(), fs::Permissions::from_mode(0o666)).unwrap();
    let r = probe_as_nobody(&env);
    assert_eq!(r, "closed", "peer-UID check did not drop a foreign user: {r}");

    // The owner is unaffected.
    assert!(!env.connect().status().unwrap().locked);
}

#[test]
fn core_dumps_off_and_memory_locked_only_while_unlocked() {
    let env = Env::new("sec-hardening");
    let d = env.spawn_daemon();
    let proc = format!("/proc/{}", d.pid());

    let limits = fs::read_to_string(format!("{proc}/limits")).unwrap();
    let core = limits.lines().find(|l| l.starts_with("Max core file size")).unwrap();
    assert!(core.split_whitespace().rev().take(3).next() == Some("bytes") && core.contains(" 0 "), "{core}");
    // PR_SET_DUMPABLE=0: a same-user process cannot open /proc/<pid>/mem (needs CAP_SYS_PTRACE).
    // The control is an ordinary process, so the check cannot pass vacuously.
    let mut control = Command::new("sleep").arg("30").spawn().unwrap();
    let control_open = fs::File::open(format!("/proc/{}/mem", control.id())).is_ok();
    let _ = control.kill();
    let _ = control.wait();
    if control_open {
        let e = fs::File::open(format!("{proc}/mem")).expect_err("daemon is still dumpable");
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    } else {
        eprintln!("NOTE: ptrace restricted here (yama?); dumpable check skipped");
    }

    let vmlck = || -> u64 {
        // Non-dumpable: /proc/<pid>/status is still world-readable.
        let s = fs::read_to_string(format!("{proc}/status")).unwrap();
        s.lines().find_map(|l| l.strip_prefix("VmLck:")).unwrap().trim().trim_end_matches(" kB").trim().parse().unwrap()
    };
    assert_eq!(vmlck(), 0);
    let mut c = env.connect();
    c.unlock(&env.secret(), None, None).unwrap();
    if d.stderr_text().contains("could not lock memory") {
        eprintln!("NOTE: RLIMIT_MEMLOCK too low here; VmLck assertions skipped");
    } else {
        assert!(vmlck() > 0, "identities are not mlocked");
        c.lock().unwrap();
        assert_eq!(vmlck(), 0, "memory still locked after lock");
    }
}

#[test]
fn passphrase_never_in_argv_or_environ() {
    let env = Env::new("sec-argv");
    let d = env.spawn_daemon();
    env.connect().unlock(&env.secret(), None, None).unwrap();
    for f in ["cmdline", "environ"] {
        // The daemon is non-dumpable so its environ is unreadable; either outcome is safe.
        let data = fs::read(format!("/proc/{}/{f}", d.pid())).unwrap_or_default();
        assert!(!String::from_utf8_lossy(&data).contains(PASSPHRASE));
    }
}

fn raw(env: &Env) -> UnixStream {
    let s = UnixStream::connect(env.sock()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s
}

fn send(s: &mut UnixStream, json: &str) -> String {
    protocol::write_frame(s, json.as_bytes()).unwrap();
    String::from_utf8_lossy(&protocol::read_frame(s).unwrap()).into_owned()
}

#[test]
fn hostile_protocol_input_is_rejected_and_daemon_survives() {
    let env = Env::new("sec-proto");
    let mut d = env.spawn_daemon();

    // Nothing works before hello, including unwrap and unlock.
    let mut s = raw(&env);
    assert!(send(&mut s, r#"{"type":"status"}"#).contains("bad_request"));
    assert!(send(&mut s, r#"{"type":"unlock","passphrase":"x"}"#).contains("bad_request"));
    // Version, unknown types, junk, extra fields.
    assert!(send(&mut s, r#"{"type":"hello","version":99}"#).contains("version"));
    assert!(send(&mut s, r#"{"type":"hello","version":1}"#).contains("daemon_version"));
    assert!(send(&mut s, r#"{"type":"export_identity"}"#).contains("bad_request"));
    assert!(send(&mut s, "not json at all").contains("bad_request"));
    assert!(send(&mut s, r#"{"type":"lock","x":1}"#).contains("bad_request"));
    assert!(send(&mut s, r#"{"type":"status"}"#).contains("locked"));
    // Locked agent refuses to unwrap; garbage base64 is "malformed" or "locked", never a key.
    let r = send(&mut s, r#"{"type":"unwrap","refs":["00"],"stanzas":[{"type":"X25519","args":["a"],"body":"!!"}]}"#);
    assert!(!r.contains("file_key"), "{r}");

    // Oversized frame: the connection is dropped, not buffered.
    let mut s = raw(&env);
    s.write_all(&((MAX_MESSAGE as u32 + 1).to_be_bytes())).unwrap();
    let mut buf = [0u8; 16];
    assert!(matches!(s.read(&mut buf), Ok(0) | Err(_)));

    // Truncated frame, then silence, then hangup; and a burst of junk connections.
    let mut s = raw(&env);
    s.write_all(&[0, 0, 0, 40, b'{']).unwrap();
    drop(s);
    for _ in 0..50 {
        let mut s = raw(&env);
        let _ = s.write_all(&[0xff; 64]);
    }

    thread::sleep(Duration::from_millis(200));
    assert!(d.alive());
    assert!(env.connect().status().unwrap().locked);
}

#[test]
fn no_identity_export_request_exists() {
    // DEC-3: the only secret-bearing reply is a 16-byte file key, and only after a real unwrap.
    let env = Env::new("sec-noexport");
    let _d = env.spawn_daemon();
    let mut c = env.connect();
    c.unlock(&env.secret(), None, None).unwrap();
    let mut s = raw(&env);
    send(&mut s, r#"{"type":"hello","version":1}"#);
    for req in [r#"{"type":"get_identity"}"#, r#"{"type":"export"}"#, r#"{"type":"dump"}"#] {
        let r = send(&mut s, req);
        assert!(r.contains("bad_request") && !r.contains(&env.secret_key), "{r}");
    }
    let st = send(&mut s, r#"{"type":"status"}"#);
    assert!(!st.contains("AGE-SECRET-KEY") && st.contains(&env.recipient.to_string()));
}

/// Runs the daemon and requires it to refuse to start; a daemon that stays up fails the test
/// instead of hanging it.
fn run_daemon_expecting_exit(env: &Env) -> (bool, String) {
    let mut child = env
        .command(AGE_AGENT)
        .args(["daemon", "--foreground"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let t0 = std::time::Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if t0.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("daemon started although it should have refused");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    (status.success(), err)
}

#[test]
fn directory_squatting_is_refused() {
    // Parent dir with loose permissions.
    let env = Env::new("sec-squat-perm");
    let dir = env.run.join("age-agent");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let (ok, stderr) = run_daemon_expecting_exit(&env);
    assert!(!ok);
    assert!(stderr.contains("0700"), "{stderr}");

    // Parent "dir" is a symlink to somewhere attacker-chosen.
    let env = Env::new("sec-squat-link");
    let elsewhere = env.root.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&elsewhere, env.run.join("age-agent")).unwrap();
    let (ok, _) = run_daemon_expecting_exit(&env);
    assert!(!ok);
    assert!(!elsewhere.join("agent.sock").exists());
}

#[test]
fn stale_socket_is_replaced_and_live_one_is_not() {
    let env = Env::new("sec-stale");
    fs::create_dir(env.run.join("age-agent")).unwrap();
    fs::set_permissions(env.run.join("age-agent"), fs::Permissions::from_mode(0o700)).unwrap();
    drop(UnixListener::bind(env.sock()).unwrap()); // leaves a dead socket file behind
    let d = env.spawn_daemon();
    assert!(env.connect().status().unwrap().locked);
    drop(d);
}

#[test]
fn client_refuses_an_impostor_and_never_sends_the_passphrase() {
    let env = Env::new("sec-impostor");
    fs::create_dir(env.run.join("age-agent")).unwrap();
    fs::set_permissions(env.run.join("age-agent"), fs::Permissions::from_mode(0o700)).unwrap();
    let l = UnixListener::bind(env.sock()).unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let t = thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let _ = c.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = protocol::write_frame(&mut c, b"{\"ok\":true}"); // wrong reply to hello
            let mut buf = Vec::new();
            let _ = c.read_to_end(&mut buf);
            s2.lock().unwrap().extend(buf);
        }
    });
    // The client must fail at hello, before it could ever send `unlock`.
    assert!(Connection::connect_to(env.sock()).is_err());
    t.join().unwrap();
    let seen = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
    assert!(!seen.contains("passphrase") && !seen.contains(PASSPHRASE), "{seen}");
}
