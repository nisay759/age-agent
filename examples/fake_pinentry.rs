//! Test fixture: a pinentry that answers with the contents of `pass.txt` next to its own
//! executable, after waiting the seconds in `delay`, and logs each `GETPIN` to
//! `pinentry.log`. Used by the Windows integration tests, which copy it per test.

use std::fs;
use std::io::{self, Write};
use std::time::Duration;

use zeroize::Zeroizing;

fn main() -> io::Result<()> {
    let dir = std::env::current_exe()?.parent().expect("exe has a parent").to_owned();
    age_agent::prompt::serve_assuan(io::stdin().lock(), &mut io::stdout().lock(), |_, _| {
        fs::OpenOptions::new().create(true).append(true).open(dir.join("pinentry.log"))?.write_all(b"getpin\n")?;
        let delay: u64 = fs::read_to_string(dir.join("delay")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        std::thread::sleep(Duration::from_secs(delay));
        Ok(Some(Zeroizing::new(fs::read_to_string(dir.join("pass.txt"))?)))
    })
}
