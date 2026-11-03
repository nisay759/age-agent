use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use age_agent::client::{self, Connection};
use age_agent::config::{self, Config, IdentityEntry};
use age_agent::{daemon, identities, prompt, stub};
use clap::{Parser, Subcommand};
use secrecy::SecretString;

#[derive(Parser)]
#[command(version, about = "Caches unlocked age identities for age clients")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write the plugin identity file and config for the given encrypted identity files
    Setup {
        /// Overwrite an existing stub file
        #[arg(long)]
        force: bool,
        /// Print the shell lines to add, then exit (or after setup)
        #[arg(long)]
        print_env: bool,
        identity_files: Vec<String>,
    },
    /// Prompt for the passphrase and load every configured identity file
    Unlock {
        /// Idle timeout for this unlock, e.g. 15m (0 = none)
        #[arg(long)]
        timeout: Option<String>,
    },
    /// Wipe all identities now
    Lock,
    /// Print lock state; exit 0 unlocked, 1 locked, 2 no daemon
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Start the daemon
    Daemon {
        #[arg(long)]
        foreground: bool,
    },
    /// Lock, then exit the daemon
    Stop,
}

fn main() -> ExitCode {
    // SEC-2 for the CLI too: `setup` holds the decrypted identity and `unlock` the passphrase.
    age_agent::sys::harden_process();
    match run(Cli::parse().command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("age-agent: {e}");
            ExitCode::from(2)
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn run(cmd: Cmd) -> Result<ExitCode> {
    match cmd {
        Cmd::Setup { force, print_env, identity_files } => setup(force, print_env, &identity_files),
        Cmd::Unlock { timeout } => {
            let timeout_s = timeout.map(|t| config::parse_duration(&t)).transpose()?.map(|d| d.as_secs());
            let mut conn = Connection::connect_or_start()?;
            // Bound to the current epoch: a lock while typing discards this unlock (LCK-1).
            let epoch = conn.status()?.epoch;
            conn.unlock_with_prompt(timeout_s, Some(epoch), |note| {
                prompt::terminal(note.unwrap_or("Unlock age-agent"))
            })?;
            print_status(&conn.status()?, false);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Lock => {
            match Connection::connect() {
                Ok(mut c) => c.lock()?,
                Err(client::Error::Io(e)) if no_daemon(&e) => {}
                Err(e) => return Err(e.into()),
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Stop => {
            match Connection::connect() {
                Ok(mut c) => c.stop()?,
                Err(client::Error::Io(e)) if no_daemon(&e) => {}
                Err(e) => return Err(e.into()),
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Status { json } => match Connection::connect() {
            Ok(mut c) => {
                let status = c.status()?;
                if json {
                    let mut v = serde_json::to_value(&status)?;
                    v["running"] = true.into();
                    println!("{v}");
                } else {
                    print_status(&status, true);
                }
                Ok(ExitCode::from(if status.locked { 1 } else { 0 }))
            }
            Err(client::Error::Io(e)) if no_daemon(&e) => {
                if json {
                    println!(
                        r#"{{"running":false,"locked":true,"recipients":[],"idle_left_s":null,"lifetime_left_s":null,"epoch":0,"prompting":false,"memory_locked":false}}"#
                    );
                } else {
                    println!("no daemon running");
                }
                Ok(ExitCode::from(2))
            }
            Err(e) => Err(e.into()),
        },
        Cmd::Daemon { foreground: true } => {
            daemon::run(config::socket_path()?, Config::load)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Daemon { foreground: false } => {
            config::socket_path()?; // fail here with the reason, not with "did not come up"
            if Connection::connect().is_ok() {
                return Err("age-agent is already running".into());
            }
            client::start_daemon()?;
            let deadline = Instant::now() + Duration::from_secs(3);
            while Connection::connect().is_err() {
                if Instant::now() > deadline {
                    return Err("daemon did not come up".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn no_daemon(e: &io::Error) -> bool {
    matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused)
}

fn print_status(s: &age_agent::protocol::Status, with_recipients: bool) {
    if s.locked {
        println!("locked");
        return;
    }
    println!("unlocked ({} identities)", s.recipients.len());
    if !s.memory_locked {
        // The daemon's own warning is lost when a plugin auto-started it with stderr closed.
        println!("warning: identities are not in locked memory (raise RLIMIT_MEMLOCK); they may reach swap");
    }
    if let Some(t) = s.idle_left_s {
        println!("idle timeout in {}", human(t));
    }
    if let Some(t) = s.lifetime_left_s {
        println!("max lifetime ends in {}", human(t));
    }
    if with_recipients {
        s.recipients.iter().for_each(|r| println!("  {r}"));
    }
}

fn human(s: u64) -> String {
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m{}s", s / 60, s % 60),
        _ => format!("{}h{}m", s / 3600, s % 3600 / 60),
    }
}

/// SET-1 to SET-4.
fn setup(force: bool, print_env: bool, files: &[String]) -> Result<ExitCode> {
    let stubs_path = config::stub_file_path()?;
    if !files.is_empty() {
        if stubs_path.exists() && !force {
            return Err(format!("{} exists; use --force to overwrite", stubs_path.display()).into());
        }
        let mut cfg = Config::load()?;
        let mut passphrase: Option<SecretString> = None;
        let mut stubs = String::from("# Written by `age-agent setup`. Holds no secret.\n");
        cfg.identities.clear();
        for file in files {
            let path = fs::canonicalize(config::expand_tilde(file)?)?;
            let loaded = load_with_prompt(&path, &mut passphrase)?;
            if loaded.is_empty() {
                return Err(format!("{} holds no identities", path.display()).into());
            }
            let mut refs = Vec::new();
            for l in &loaded {
                stubs += &format!("# recipient: {}\n{}\n", l.recipient, stub::encode(&l.reference));
                refs.push(stub::ref_hex(&l.reference));
            }
            cfg.identities.push(IdentityEntry { file: tilde(&path), refs });
        }
        let dir = stubs_path.parent().expect("stub path has a parent");
        fs::create_dir_all(dir)?;
        fs::write(&stubs_path, stubs)?;
        fs::set_permissions(&stubs_path, fs::Permissions::from_mode(0o644))?;
        cfg.save()?;
        println!("wrote {} and {}", stubs_path.display(), config::config_path()?.display());
    } else if !print_env {
        return Err("give at least one identity file".into());
    }
    if print_env || !files.is_empty() {
        println!("export PASSAGE_IDENTITIES_FILE={}", stubs_path.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// Asks the passphrase once for the first encrypted file and reuses it for the rest.
fn load_with_prompt(path: &Path, passphrase: &mut Option<SecretString>) -> Result<Vec<identities::Loaded>> {
    if !identities::is_encrypted(path)? {
        return Ok(identities::load(path, None)?);
    }
    for attempt in 0..client::UNLOCK_ATTEMPTS {
        if passphrase.is_none() {
            let msg = if attempt == 0 { format!("Passphrase for {}", path.display()) } else { "Wrong passphrase, try again.".into() };
            *passphrase = Some(prompt::terminal(&msg)?);
        }
        match identities::load(path, passphrase.as_ref()) {
            Err(identities::LoadError::BadPassphrase) => *passphrase = None,
            r => return Ok(r?),
        }
    }
    Err("wrong passphrase".into())
}

fn tilde(p: &Path) -> String {
    match config::home().ok().and_then(|h| p.strip_prefix(h).ok().map(|r| r.to_path_buf())) {
        Some(rest) => format!("~/{}", rest.display()),
        None => p.display().to_string(),
    }
}
