//! Real clients (`age`, `rage`, `passage`) against the real daemon and plugin, run without a
//! terminal like rofi would. Each test skips when its client is not installed.

mod common;

use std::process::{Child, Output, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

use age_agent::client::Connection;
use common::*;

fn have(bin: &str) -> bool {
    let found = std::process::Command::new("sh")
        .args(["-c", &format!("command -v {bin}")])
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !found {
        eprintln!("SKIPPED: {bin} not installed");
    }
    found
}

fn ok_stdout(out: Output) -> String {
    assert!(out.status.success(), "client failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn encrypted_file(env: &Env, msg: &str) -> String {
    let f = env.root.join("secret.age");
    fs::write(&f, env.ciphertext(msg.as_bytes())).unwrap();
    f.display().to_string()
}

fn decrypt(env: &Env, client: &str, file: &str) -> Output {
    let stubs = env.stubs_file().display().to_string();
    env.client(&[client, "-d", "-i", &stubs, file]).output().unwrap()
}

fn spawn_decrypt(env: &Env, file: &str) -> Child {
    let stubs = env.stubs_file().display().to_string();
    env.client(&["age", "-d", "-i", &stubs, file]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(10), "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

fn prompting(env: &Env) -> bool {
    Connection::connect_to(env.sock()).and_then(|mut c| c.status()).is_ok_and(|s| s.prompting)
}

fn finish(mut child: Child, within: Duration) -> Output {
    let t0 = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if t0.elapsed() > within {
            let _ = child.kill();
            panic!("client still running after {within:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn age_and_rage_share_one_unlock() {
    if !have("age") || !have("rage") {
        return;
    }
    let env = Env::new("cli-agerage");
    env.set_prompt_mode("auto");
    let f = encrypted_file(&env, "hello");
    // No daemon yet: the plugin starts it, request-secret fails (no tty), pinentry asks once.
    assert_eq!(ok_stdout(decrypt(&env, "age", &f)), "hello");
    assert_eq!(env.prompts(), 1);
    assert_eq!(ok_stdout(decrypt(&env, "rage", &f)), "hello");
    assert_eq!(ok_stdout(decrypt(&env, "age", &f)), "hello");
    assert_eq!(env.prompts(), 1);
}

/// Acceptance: unlocked, 100 `passage show` calls prompt never; locked, the first prompts
/// once and the other 99 do not.
#[test]
fn passage_show_100_times() {
    if !have("passage") || !have("age") {
        return;
    }
    let env = Env::new("cli-passage");
    env.set_prompt_mode("auto");
    let store = env.home.join(".passage/store");
    fs::create_dir_all(store.join("web/shop")).unwrap();
    fs::write(store.join(".age-recipients"), format!("{}\n", env.recipient)).unwrap();
    fs::write(store.join("web/shop/example.com.age"), env.ciphertext(b"s3cret-pw\nuser: me\n")).unwrap();

    let show = || {
        let out = env
            .client(&["passage", "show", "web/shop/example.com"])
            .env("PASSAGE_DIR", &store)
            .env("PASSAGE_IDENTITIES_FILE", env.stubs_file())
            .output()
            .unwrap();
        assert_eq!(ok_stdout(out), "s3cret-pw\nuser: me\n");
    };
    for _ in 0..100 {
        show();
    }
    assert_eq!(env.prompts(), 1, "locked: only the first call may prompt");

    // Unlocked (already): 100 more, no prompt at all.
    for _ in 0..100 {
        show();
    }
    assert_eq!(env.prompts(), 1, "unlocked: no call may prompt");

    // After `age-agent lock`, the next call prompts again, once.
    let lock = env.command(AGE_AGENT).arg("lock").status().unwrap();
    assert!(lock.success());
    for _ in 0..5 {
        show();
    }
    assert_eq!(env.prompts(), 2);
}

/// LCK-1: `age-agent lock` cancels a pinentry that is still waiting for the user.
#[test]
fn lock_cancels_a_pending_prompt() {
    if !have("age") {
        return;
    }
    let env = Env::new("cli-cancel");
    env.set_prompt_mode("auto");
    env.set_pinentry_delay(60);
    let f = encrypted_file(&env, "hello");
    let child = spawn_decrypt(&env, &f);
    wait_until("the prompt to open", || prompting(&env) && env.prompts() == 1);

    let t0 = Instant::now();
    assert!(env.command(AGE_AGENT).arg("lock").status().unwrap().success());
    let out = finish(child, Duration::from_secs(5));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cancelled"), "{out:?}");
    assert!(t0.elapsed() < Duration::from_secs(3), "prompt was not cancelled promptly");
    assert!(!prompting(&env));
    assert!(env.connect().status().unwrap().locked);

    // The agent is usable afterwards.
    env.set_pinentry_delay(0);
    assert_eq!(ok_stdout(decrypt(&env, "age", &f)), "hello");
}

/// Open question 3: concurrent clients queue behind one prompt instead of each prompting.
#[test]
fn concurrent_clients_prompt_once() {
    if !have("age") {
        return;
    }
    let env = Env::new("cli-concurrent");
    env.set_prompt_mode("auto");
    env.set_pinentry_delay(1);
    let f = encrypted_file(&env, "hello");
    // Start the daemon first so the clients don't race to auto-start it.
    let _d = env.spawn_daemon();
    let children: Vec<_> = (0..6).map(|_| spawn_decrypt(&env, &f)).collect();
    for c in children {
        let out = finish(c, Duration::from_secs(15));
        assert_eq!(ok_stdout(out), "hello");
    }
    assert_eq!(env.prompts(), 1);
}

/// A prompt becomes pointless when another client (e.g. the GUI over the socket) unlocks:
/// it is closed and the waiting decryption goes through.
#[test]
fn unlock_elsewhere_closes_the_prompt() {
    if !have("age") {
        return;
    }
    let env = Env::new("cli-elsewhere");
    env.set_prompt_mode("auto");
    env.set_pinentry_delay(60);
    let f = encrypted_file(&env, "hello");
    let child = spawn_decrypt(&env, &f);
    wait_until("the prompt to open", || prompting(&env));
    env.connect().unlock(&env.secret(), None, None).unwrap();
    let out = finish(child, Duration::from_secs(5));
    assert_eq!(ok_stdout(out), "hello");
}

/// Open question 1: with no terminal, request-secret fails at once in age and rage (no hang),
/// so `mode = "terminal"` reports an error and `auto` can fall back to pinentry.
#[test]
fn request_secret_fails_fast_without_a_terminal() {
    for client in ["age", "rage"] {
        if !have(client) {
            continue;
        }
        let env = Env::new(&format!("cli-notty-{client}"));
        env.set_prompt_mode("terminal");
        let f = encrypted_file(&env, "hello");
        let _d = env.spawn_daemon();
        let t0 = Instant::now();
        let out = decrypt(&env, client, &f);
        assert!(!out.status.success());
        assert!(t0.elapsed() < Duration::from_secs(5), "{client} hung on request-secret");
        assert_eq!(env.prompts(), 0);
    }
}

/// LCK-1 for prompts that cannot be killed (age's own terminal prompt): an unlock bound to
/// the epoch its prompt started in is refused after a lock.
#[test]
fn unlock_from_a_stale_epoch_is_refused() {
    let env = Env::new("cli-epoch");
    let _d = env.spawn_daemon();
    let mut c = env.connect();
    let epoch = c.status().unwrap().epoch;
    c.lock().unwrap();
    let err = c.unlock(&env.secret(), None, Some(epoch)).unwrap_err();
    assert_eq!(err.code(), Some("cancelled"));
    assert!(c.status().unwrap().locked);
    let epoch = c.status().unwrap().epoch;
    c.unlock(&env.secret(), None, Some(epoch)).unwrap();
    assert!(!c.status().unwrap().locked);
}
