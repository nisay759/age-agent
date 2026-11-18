//! Passphrase prompts: the controlling terminal, a pinentry program (UNL-2), or on Windows
//! the native credential dialog (UNL-5), which runs as a built-in pinentry.

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::config::PromptConfig;

#[cfg(unix)]
const TTY: &str = "/dev/tty";
#[cfg(windows)]
const TTY: &str = "CONOUT$";

/// rpassword reads from the terminal (`/dev/tty`, or the Windows console) with echo off,
/// so this works under pipes and plugins.
pub fn terminal(message: &str) -> io::Result<SecretString> {
    let mut tty = File::options().write(true).open(TTY)?;
    writeln!(tty, "{message}")?;
    rpassword::prompt_password("Passphrase: ").map(SecretString::from)
}

/// Fixed locations searched when `prompt.pinentry` is unset (SEC-8).
#[cfg(unix)]
fn system_pinentries() -> Vec<PathBuf> {
    ["/usr/bin/pinentry", "/usr/local/bin/pinentry", "/opt/homebrew/bin/pinentry", "/usr/bin/pinentry-mac"]
        .iter()
        .map(PathBuf::from)
        .collect()
}

/// Gpg4win's and GnuPG's pinentries under Program Files, located through the shell's
/// known folders, not the environment.
#[cfg(windows)]
fn system_pinentries() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in crate::sys::program_files_dirs() {
        out.push(dir.join(r"Gpg4win\bin\pinentry.exe"));
        out.push(dir.join(r"GnuPG\bin\pinentry-basic.exe"));
    }
    out
}

/// SEC-8: the pinentry path comes from the config file and must be absolute. With no
/// config, only fixed system locations are searched, never the caller's `PATH`.
pub fn pinentry_path(cfg: &PromptConfig) -> io::Result<PathBuf> {
    if let Some(p) = &cfg.pinentry {
        let p = Path::new(p);
        if !p.is_absolute() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "prompt.pinentry must be an absolute path"));
        }
        return Ok(p.to_path_buf());
    }
    system_pinentries()
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no pinentry found; set prompt.pinentry in config.toml"))
}

/// Lets another thread abort a prompt (LCK-1). A running pinentry is killed; a prompt that
/// cannot be killed (age's `request-secret`) has its answer discarded instead.
#[derive(Default)]
pub struct Cancel {
    pid: Mutex<Option<u32>>,
    cancelled: AtomicBool,
}

impl Cancel {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(pid) = *self.pid.lock().unwrap_or_else(|e| e.into_inner()) {
            crate::sys::terminate(pid);
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn check(&self) -> io::Result<()> {
        match self.is_cancelled() {
            true => Err(io::Error::new(io::ErrorKind::Interrupted, "prompt cancelled")),
            false => Ok(()),
        }
    }
}

/// Minimal Assuan client: `GETPIN`. The pinentry's stdout is read without a `BufReader`,
/// whose buffer would keep an unzeroized copy of the `D <passphrase>` line.
pub fn pinentry(path: &Path, description: &str, cancel: &Cancel) -> io::Result<SecretString> {
    pinentry_command(Command::new(path), description, cancel)
}

/// UNL-5: the Windows credential dialog, shown by `age-agent native-pinentry` so that a
/// lock can cancel it by killing that process, like any pinentry.
#[cfg(windows)]
pub fn native(description: &str, cancel: &Cancel) -> io::Result<SecretString> {
    let mut cmd = Command::new(crate::client::sibling_binary("age-agent")?);
    cmd.arg("native-pinentry");
    pinentry_command(cmd, description, cancel)
}

fn pinentry_command(mut cmd: Command, description: &str, cancel: &Cancel) -> io::Result<SecretString> {
    cancel.check()?;
    #[cfg(windows)]
    {
        // A console pinentry (or our own) must not flash a console window.
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    *cancel.pid.lock().unwrap_or_else(|e| e.into_inner()) = Some(child.id());
    if cancel.is_cancelled() {
        crate::sys::terminate(child.id()); // cancelled between the check and the spawn
    }
    let mut stdin = child.stdin.take().expect("piped");
    let mut out = child.stdout.take().expect("piped");
    let result = assuan_getpin(&mut out, &mut stdin, description);
    let _ = writeln!(stdin, "BYE");
    drop(stdin);
    // Forget the pid before reaping, so `cancel` can never signal a recycled pid.
    *cancel.pid.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let _ = child.wait();
    cancel.check()?;
    result
}

/// Assuan lines are at most 1000 bytes; anything longer is not a pinentry talking.
const MAX_LINE: usize = 4096;

/// Reads one line into `line`, which keeps its (zeroized) allocation across calls so the
/// passphrase is never copied by a reallocation.
fn read_line(r: &mut impl Read, line: &mut Zeroizing<Vec<u8>>) -> io::Result<()> {
    let proto = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m);
    line.clear();
    let mut b = [0u8; 1];
    loop {
        if r.read(&mut b)? == 0 {
            return Err(proto("pinentry closed the connection"));
        }
        if b[0] == b'\n' {
            return Ok(());
        }
        if line.len() == MAX_LINE {
            return Err(proto("pinentry sent an oversized line"));
        }
        line.push(b[0]);
    }
}

fn assuan_getpin(out: &mut impl Read, inp: &mut impl Write, description: &str) -> io::Result<SecretString> {
    let proto = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    let mut pin = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    read_line(out, &mut line)?;
    if !line.starts_with(b"OK") {
        return Err(proto(format!("unexpected pinentry greeting: {}", String::from_utf8_lossy(&line))));
    }
    for cmd in [
        "SETTITLE age-agent\n".to_string(),
        format!("SETDESC {}\n", escape(description)),
        "SETPROMPT Passphrase:\n".to_string(),
        "GETPIN\n".to_string(),
    ] {
        inp.write_all(cmd.as_bytes())?;
        inp.flush()?;
        if cmd == "GETPIN\n" {
            loop {
                read_line(out, &mut line)?;
                if let Some(d) = line.strip_prefix(b"D ") {
                    // Long answers may arrive as several `D` lines; they concatenate.
                    unescape_into(d.strip_suffix(b"\r").unwrap_or(d), &mut pin)?;
                } else if line.starts_with(b"OK") {
                    if pin.is_empty() {
                        return Err(proto("pinentry returned no passphrase".into()));
                    }
                    let s = std::str::from_utf8(&pin).map_err(|_| proto("pinentry returned invalid UTF-8".into()))?;
                    return Ok(SecretString::from(s));
                } else if line.starts_with(b"ERR") {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "passphrase entry cancelled"));
                }
            }
        }
        read_line(out, &mut line)?;
        if !line.starts_with(b"OK") {
            return Err(proto(format!("pinentry rejected setup: {}", String::from_utf8_lossy(&line))));
        }
    }
    unreachable!("GETPIN is the last command")
}

fn escape(s: &str) -> String {
    s.replace('%', "%25").replace('\n', "%0A").replace('\r', "%0D")
}

/// Assuan `%XX` decoding, appended to `dst` (which the caller sized so it never grows).
fn unescape_into(src: &[u8], dst: &mut Vec<u8>) -> io::Result<()> {
    let mut i = 0;
    while i < src.len() {
        if dst.len() == dst.capacity() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "pinentry answer too long"));
        }
        let hex = src.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match (src[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                dst.push(v);
                i += 3;
            }
            (c, _) => {
                dst.push(c);
                i += 1;
            }
        }
    }
    Ok(())
}

/// The server half of the Assuan exchange above, enough for `age-agent native-pinentry`:
/// `SETTITLE`, `SETDESC`, `GETPIN` and `BYE`, `OK` to anything else. `getpin(title, desc)`
/// returns `None` when the user cancels. Each `D` line is built and written in one call
/// from a zeroized buffer.
pub fn serve_assuan(
    input: impl BufRead,
    out: &mut impl Write,
    mut getpin: impl FnMut(&str, &str) -> io::Result<Option<Zeroizing<String>>>,
) -> io::Result<()> {
    let (mut title, mut desc) = (String::from("age-agent"), String::new());
    out.write_all(b"OK age-agent native pinentry\n")?;
    for line in input.lines() {
        let line = line?;
        let (cmd, arg) = line.split_once(' ').unwrap_or((&line, ""));
        let decode = |s: &str| {
            let mut v = Vec::with_capacity(s.len());
            unescape_into(s.as_bytes(), &mut v).map(|()| String::from_utf8_lossy(&v).into_owned())
        };
        match cmd {
            "SETTITLE" => title = decode(arg)?,
            "SETDESC" => desc = decode(arg)?,
            "BYE" => return out.write_all(b"OK closing connection\n"),
            "GETPIN" => {
                match getpin(&title, &desc) {
                    Ok(Some(pin)) => {
                        let mut reply = Zeroizing::new(Vec::with_capacity(pin.len() * 3 + 8));
                        reply.extend_from_slice(b"D ");
                        for &b in pin.as_bytes() {
                            match b {
                                b'%' | b'\r' | b'\n' => reply.extend_from_slice(format!("%{b:02X}").as_bytes()),
                                b => reply.push(b),
                            }
                        }
                        reply.extend_from_slice(b"\nOK\n");
                        out.write_all(&reply)?;
                    }
                    Ok(None) => out.write_all(b"ERR 83886179 Operation cancelled\n")?,
                    Err(e) => out.write_all(format!("ERR 83886081 {}\n", escape(&e.to_string())).as_bytes())?,
                }
                out.flush()?;
                continue;
            }
            _ => {}
        }
        out.write_all(b"OK\n")?;
        out.flush()?;
    }
    Ok(())
}

/// `age-agent native-pinentry`: a pinentry on stdio backed by the Windows credential dialog.
#[cfg(windows)]
pub fn run_native_pinentry() -> io::Result<()> {
    serve_assuan(io::stdin().lock(), &mut io::stdout().lock(), |title, desc| {
        crate::sys::credential_prompt(title, desc)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn assuan_server_talks_to_our_client() {
        use std::io::Cursor;
        let mut requests = Vec::new();
        // Drive the client against a canned transcript of what our server answers.
        let mut server_out = Vec::new();
        let script = "SETTITLE age-agent\nSETDESC Wrong%0Aagain\nSETPROMPT Passphrase:\nGETPIN\nBYE\n";
        serve_assuan(Cursor::new(script), &mut server_out, |title, desc| {
            requests.push((title.to_owned(), desc.to_owned()));
            Ok(Some(Zeroizing::new("p%ss\nwörd".to_owned())))
        })
        .unwrap();
        assert_eq!(requests, [("age-agent".to_owned(), "Wrong\nagain".to_owned())]);
        let pin = assuan_getpin(&mut server_out.as_slice(), &mut Vec::new(), "x").unwrap();
        assert_eq!(pin.expose_secret(), "p%ss\nwörd");

        let mut cancelled = Vec::new();
        serve_assuan(Cursor::new("GETPIN\n"), &mut cancelled, |_, _| Ok(None)).unwrap();
        let text = String::from_utf8(cancelled).unwrap();
        assert!(text.ends_with("ERR 83886179 Operation cancelled\n"), "{text}");
    }

    #[test]
    fn assuan_exchange() {
        let mut out = "OK ready\nOK\nOK\nOK\nD pa%25ss\nOK\n".as_bytes();
        let mut sent = Vec::new();
        let pin = assuan_getpin(&mut out, &mut sent, "unlock\nnow").unwrap();
        assert_eq!(pin.expose_secret(), "pa%ss");
        let sent = String::from_utf8(sent).unwrap();
        assert!(sent.contains("SETDESC unlock%0Anow\n"));
        assert!(sent.ends_with("GETPIN\n"));
    }

    #[test]
    fn split_and_crlf_data_lines() {
        let mut out = "OK\nOK\nOK\nOK\nD first-\r\nD %C3%A9nd\nOK\n".as_bytes();
        let pin = assuan_getpin(&mut out, &mut Vec::new(), "x").unwrap();
        assert_eq!(pin.expose_secret(), "first-énd");
    }

    #[test]
    fn cancel_is_an_error() {
        let mut out = "OK\nOK\nOK\nOK\nERR 83886179 canceled\n".as_bytes();
        assert!(assuan_getpin(&mut out, &mut Vec::new(), "x").is_err());
    }

    #[test]
    fn hostile_pinentry_output() {
        let long = format!("OK\nOK\nOK\nOK\nD {}\nOK\n", "a".repeat(MAX_LINE + 1));
        assert!(assuan_getpin(&mut long.as_bytes(), &mut Vec::new(), "x").is_err());
        let mut eof = "OK\nOK\nOK\nOK\nD partial".as_bytes();
        assert!(assuan_getpin(&mut eof, &mut Vec::new(), "x").is_err());
        let mut bad_utf8 = "OK\nOK\nOK\nOK\nD %FF\nOK\n".as_bytes();
        assert!(assuan_getpin(&mut bad_utf8, &mut Vec::new(), "x").is_err());
        let mut empty = "OK\nOK\nOK\nOK\nOK\n".as_bytes();
        assert!(assuan_getpin(&mut empty, &mut Vec::new(), "x").is_err());
    }

    #[test]
    fn relative_pinentry_rejected() {
        let cfg = PromptConfig { mode: "auto".into(), pinentry: Some("pinentry".into()) };
        assert!(pinentry_path(&cfg).is_err());
    }
}
