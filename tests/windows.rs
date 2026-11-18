//! M3 on Windows: the real daemon and plugin over the named pipe, driven by
//! `examples/age_decrypt` (the `age` crate's plugin client, no terminal, like a GUI) with
//! `examples/fake_pinentry`. Each test runs its own agent through `AGE_AGENT_INSTANCE`.
#![cfg(windows)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::{fs, iter, thread};

use age::secrecy::{ExposeSecret, SecretString};
use age::{Encryptor, x25519};
use age_agent::client::Connection;
use age_agent::{stub, sys};

const PASSPHRASE: &str = "correct horse battery staple";
const AGE_AGENT: &str = env!("CARGO_BIN_EXE_age-agent");

fn bin_dir() -> PathBuf {
    Path::new(AGE_AGENT).parent().unwrap().to_owned()
}

/// `cargo test` builds the examples next to the binaries.
fn example(name: &str) -> PathBuf {
    let p = bin_dir().join("examples").join(format!("{name}.exe"));
    assert!(p.exists(), "{} missing: run `cargo test` (which builds examples), not `--test windows` alone", p.display());
    p
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

struct Env {
    root: PathBuf,
    cfg_home: PathBuf,
    fixtures: PathBuf,
    instance: String,
    pipe: PathBuf,
    recipient: x25519::Recipient,
}

impl Env {
    fn new(name: &str) -> Env {
        Self::with_config(name, "")
    }

    fn with_config(name: &str, extra: &str) -> Env {
        let root = std::env::temp_dir().join(format!("age-agent-win-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (home, fixtures) = (root.join("home"), root.join("fixtures"));
        let cfg_home = home.join(".config");
        fs::create_dir_all(cfg_home.join("age-agent")).unwrap();
        fs::create_dir_all(&fixtures).unwrap();

        let id = x25519::Identity::generate();
        let recipient = id.to_public();
        let e = Encryptor::with_user_passphrase(SecretString::from(PASSPHRASE.to_owned()));
        let mut buf = Vec::new();
        let mut w = e.wrap_output(&mut buf).unwrap();
        w.write_all(format!("{}\n", id.to_string().expose_secret()).as_bytes()).unwrap();
        w.finish().unwrap();
        let id_file = home.join("identities");
        fs::write(&id_file, buf).unwrap();

        let pinentry = fixtures.join("pinentry.exe");
        fs::copy(example("fake_pinentry"), &pinentry).unwrap();
        fs::write(fixtures.join("pass.txt"), PASSPHRASE).unwrap();
        fs::write(fixtures.join("delay"), "0").unwrap();

        let reference = stub::reference(&recipient.to_string());
        fs::write(
            cfg_home.join("age-agent/config.toml"),
            format!(
                "[[identity]]\nfile = '{}'\nrefs = ['{}']\n[prompt]\nmode = 'pinentry'\npinentry = '{}'\n{extra}",
                id_file.display(),
                stub::ref_hex(&reference),
                pinentry.display()
            ),
        )
        .unwrap();
        fs::write(
            cfg_home.join("age-agent/identities.txt"),
            format!("# recipient: {recipient}\n{}\n", stub::encode(&reference)),
        )
        .unwrap();
        let instance = format!("test-{name}-{}", std::process::id());
        let pipe = PathBuf::from(format!(r"\\.\pipe\age-agent-{}-{instance}", sys::current_sid().unwrap()));
        Env { root, cfg_home, fixtures, instance, pipe, recipient }
    }

    fn command(&self, bin: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut c = Command::new(bin);
        let path = format!("{};{}", bin_dir().display(), std::env::var("PATH").unwrap_or_default());
        c.env("XDG_CONFIG_HOME", &self.cfg_home)
            .env("HOME", self.root.join("home"))
            .env("AGE_AGENT_INSTANCE", &self.instance)
            .env("PATH", path);
        c
    }

    fn spawn_daemon(&self) -> DaemonProc {
        let child = self
            .command(AGE_AGENT)
            .args(["daemon", "--foreground"])
            .stdout(Stdio::null())
            .stderr(fs::File::create(self.root.join("daemon.stderr")).unwrap())
            .spawn()
            .unwrap();
        wait_for("daemon to come up", Duration::from_secs(5), || Connection::connect_to(self.pipe.clone()).is_ok());
        DaemonProc(child)
    }

    fn connect(&self) -> Connection {
        Connection::connect_to(self.pipe.clone()).unwrap()
    }

    fn locked(&self) -> bool {
        self.connect().status().unwrap().locked
    }

    fn encrypted(&self, msg: &str) -> PathBuf {
        let e = Encryptor::with_recipients(iter::once(&self.recipient as &dyn age::Recipient)).unwrap();
        let mut buf = Vec::new();
        let mut w = e.wrap_output(&mut buf).unwrap();
        w.write_all(msg.as_bytes()).unwrap();
        w.finish().unwrap();
        let p = self.root.join(format!("{}.age", msg.len()));
        fs::write(&p, buf).unwrap();
        p
    }

    /// `AGE_AGENT_TEST_CLIENT=<path to age.exe or rage.exe>` runs every decryption through
    /// that client instead of `examples/age_decrypt`.
    fn decrypt_cmd(&self, file: &Path) -> Command {
        let ids = self.cfg_home.join("age-agent/identities.txt");
        let mut c = match std::env::var_os("AGE_AGENT_TEST_CLIENT") {
            Some(client) => {
                let mut c = self.command(client);
                c.arg("-d").arg("-i").arg(ids).arg(file);
                c
            }
            None => {
                let mut c = self.command(example("age_decrypt"));
                c.arg(ids).arg(file);
                c
            }
        };
        c.stdin(Stdio::null());
        c
    }

    fn decrypt(&self, file: &Path) -> Output {
        self.decrypt_cmd(file).output().unwrap()
    }

    fn prompts(&self) -> usize {
        fs::read_to_string(self.fixtures.join("pinentry.log")).map(|s| s.lines().count()).unwrap_or(0)
    }

    fn unlock(&self) {
        self.connect().unlock(&SecretString::from(PASSPHRASE.to_owned()), None, None).unwrap();
    }

    /// The daemon's hidden notification window, which is titled with the pipe name.
    fn window(&self) -> windows_sys::Win32::Foundation::HWND {
        use windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW;
        let (class, title) = (wide("age-agent-notify"), wide(&self.pipe.display().to_string()));
        let mut hwnd = std::ptr::null_mut();
        wait_for("notification window", Duration::from_secs(5), || {
            // SAFETY: valid NUL-terminated strings.
            hwnd = unsafe { FindWindowW(class.as_ptr(), title.as_ptr()) };
            !hwnd.is_null()
        });
        hwnd
    }

    fn send(&self, msg: u32, wparam: u32) {
        use windows_sys::Win32::UI::WindowsAndMessaging::SendMessageW;
        // SAFETY: a live window handle and plain integer arguments.
        unsafe { SendMessageW(self.window(), msg, wparam as usize, 0) };
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Daemons auto-started by the plugin are not our children; stop them here.
        if let Ok(mut c) = Connection::connect_to(self.pipe.clone()) {
            let _ = c.stop();
        }
        if !thread::panicking() {
            thread::sleep(Duration::from_millis(200));
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

/// A daemon we spawned; killed and reaped on drop.
struct DaemonProc(Child);

impl Drop for DaemonProc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for(what: &str, within: Duration, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < within, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(25));
    }
}

fn ok_stdout(out: Output) -> String {
    assert!(out.status.success(), "decrypt failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn exits_within(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let t0 = Instant::now();
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        if t0.elapsed() > within {
            let _ = child.kill();
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn auto_start_prompt_once_then_lock() {
    let env = Env::new("session");
    let file = env.encrypted("hello windows");
    assert!(Connection::connect_to(env.pipe.clone()).is_err(), "no daemon yet");

    // DMN-1: the plugin starts a detached daemon, then UNL-2 prompts through pinentry.
    assert_eq!(ok_stdout(env.decrypt(&file)), "hello windows");
    assert_eq!(env.prompts(), 1);
    // The daemon outlived the plugin that started it.
    let st = env.connect().status().unwrap();
    assert!(!st.locked);
    assert!(st.memory_locked, "SEC-1: identities should sit in VirtualLock'ed memory");

    for _ in 0..10 {
        assert_eq!(ok_stdout(env.decrypt(&file)), "hello windows");
    }
    assert_eq!(env.prompts(), 1, "an unlocked agent never prompts");

    // LCK-1: after a lock, the next decryption prompts again.
    env.connect().lock().unwrap();
    assert!(env.locked());
    assert_eq!(ok_stdout(env.decrypt(&file)), "hello windows");
    assert_eq!(env.prompts(), 2);
}

#[test]
fn concurrent_decryptions_share_one_prompt() {
    let env = Env::new("concurrent");
    let _d = env.spawn_daemon();
    fs::write(env.fixtures.join("delay"), "2").unwrap();
    let file = env.encrypted("together");
    let children: Vec<_> = (0..5).map(|_| env.decrypt_cmd(&file).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()).collect();
    for c in children {
        assert_eq!(ok_stdout(c.wait_with_output().unwrap()), "together");
    }
    assert_eq!(env.prompts(), 1);
}

#[test]
fn lock_cancels_a_pending_prompt() {
    let env = Env::new("cancel");
    let _d = env.spawn_daemon();
    fs::write(env.fixtures.join("delay"), "60").unwrap();
    let file = env.encrypted("never");
    let mut child = env.decrypt_cmd(&file).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    wait_for("the prompt", Duration::from_secs(10), || env.prompts() == 1);
    env.connect().lock().unwrap();
    let status = exits_within(&mut child, Duration::from_secs(5)).expect("the pending prompt was not cancelled");
    assert!(!status.success());
    let mut err = String::new();
    child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    assert!(err.contains("cancelled"), "{err}");
    assert!(env.locked());
}

#[test]
fn session_lock_suspend_and_logoff_messages() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND, WM_ENDSESSION, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE,
        WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
    };
    let env = Env::new("autolock");
    let mut d = env.spawn_daemon();
    let within_a_second = |what| wait_for(what, Duration::from_secs(1), || env.locked());

    env.unlock();
    env.send(WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK);
    env.send(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC);
    assert!(!env.locked(), "harmless notifications must not lock");
    env.send(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK);
    within_a_second("lock on session lock");

    env.unlock();
    env.send(WM_POWERBROADCAST, PBT_APMSUSPEND);
    within_a_second("lock on suspend");

    // LCK-4: log-off wipes and exits.
    env.unlock();
    env.send(WM_ENDSESSION, 1);
    assert!(exits_within(&mut d.0, Duration::from_secs(2)).is_some(), "daemon did not exit on WM_ENDSESSION");
}

#[test]
fn config_flags_turn_triggers_off() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        PBT_APMSUSPEND, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK,
    };
    let env = Env::with_config("flags", "[agent]\nlock_on_screen_lock = false\nlock_on_suspend = false\n");
    let _d = env.spawn_daemon();
    env.unlock();
    env.send(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK);
    env.send(WM_POWERBROADCAST, PBT_APMSUSPEND);
    thread::sleep(Duration::from_millis(300));
    assert!(!env.locked());
}

#[test]
fn second_daemon_refuses_to_start_and_stop_exits() {
    let env = Env::new("dmn2");
    let mut d = env.spawn_daemon();
    let out = env.command(AGE_AGENT).args(["daemon", "--foreground"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already running"), "{out:?}");

    env.connect().stop().unwrap();
    assert!(exits_within(&mut d.0, Duration::from_secs(2)).is_some(), "daemon did not exit on stop");
    let status = env.command(AGE_AGENT).args(["status"]).output().unwrap();
    assert_eq!(status.status.code(), Some(2), "STA-1: no daemon");
}

/// SEC-5: a pipe created before the daemon is never joined, and a client talking to it
/// gives up instead of hanging.
#[test]
fn squatted_pipe_is_detected() {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE};
    let env = Env::new("squat");
    let name = wide(&env.pipe.display().to_string());
    // SAFETY: valid name; default security; closed below.
    let squatter = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 4, 4096, 4096, 0, std::ptr::null()) };
    assert_ne!(squatter, INVALID_HANDLE_VALUE);

    let mut d = env.command(AGE_AGENT).args(["daemon", "--foreground"]).stderr(Stdio::piped()).spawn().unwrap();
    let status = exits_within(&mut d, Duration::from_secs(15)).expect("daemon should refuse the squatted name");
    assert!(!status.success());

    let t0 = Instant::now();
    assert!(Connection::connect_to(env.pipe.clone()).is_err(), "a squatter that never answers is not a daemon");
    assert!(t0.elapsed() < Duration::from_secs(10));
    // SAFETY: our own handle, closed once.
    unsafe { CloseHandle(squatter) };
}

#[test]
fn hostile_protocol_input_is_rejected_and_daemon_survives() {
    let env = Env::new("hostile");
    let _d = env.spawn_daemon();
    let exchange = |payload: &[u8]| -> String {
        let mut s = sys::connect(&env.pipe).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(payload).unwrap();
        let mut len = [0u8; 4];
        if s.read_exact(&mut len).is_err() {
            return String::new(); // the daemon hung up, which is fine
        }
        let mut buf = vec![0; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    };
    let frame = |json: &str| [&(json.len() as u32).to_be_bytes()[..], json.as_bytes()].concat();
    assert_eq!(exchange(&(u32::MAX).to_be_bytes()), "");
    assert!(exchange(&frame("{\"type\":\"status\"}")).contains("expected hello first"));
    assert!(exchange(&frame("not json")).contains("bad_request"));
    assert!(exchange(&frame("{\"type\":\"export\"}")).contains("bad_request"));
    assert!(env.connect().status().unwrap().locked, "daemon still serves");
}

/// SEC-2: same-user processes may query and terminate the daemon, not read its memory.
#[test]
fn daemon_memory_is_not_readable_by_same_user_processes() {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };
    let env = Env::new("dacl");
    let d = env.spawn_daemon();
    env.unlock();
    for (access, allowed) in [
        (PROCESS_VM_READ, false),
        (PROCESS_VM_WRITE, false),
        (PROCESS_QUERY_LIMITED_INFORMATION, true),
        (PROCESS_TERMINATE, true),
    ] {
        // SAFETY: OpenProcess has no memory preconditions; the handle is closed below.
        let h = unsafe { OpenProcess(access, 0, d.0.id()) };
        assert_eq!(!h.is_null(), allowed, "access {access:#x}");
        if !h.is_null() {
            unsafe { CloseHandle(h) };
        }
    }
}

/// UNL-5 plumbing: `age-agent native-pinentry` speaks Assuan (GETPIN is not sent here: it
/// would open the credential dialog).
#[test]
fn native_pinentry_speaks_assuan() {
    let mut p = Command::new(AGE_AGENT).arg("native-pinentry").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = p.stdin.take().unwrap();
    let mut out = BufReader::new(p.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    assert!(line.starts_with("OK"), "{line}");
    for cmd in ["SETTITLE age-agent", "SETDESC Unlock%0Aage-agent", "BYE"] {
        writeln!(stdin, "{cmd}").unwrap();
        line.clear();
        out.read_line(&mut line).unwrap();
        assert!(line.starts_with("OK"), "{cmd}: {line}");
    }
    assert!(p.wait().unwrap().success());
}
