//! Test fixture: `age -d -i <identities> <file>` without a terminal, built on the `age`
//! crate's plugin client (the code `rage` uses). Its callbacks refuse `request-secret`, as
//! age does with no terminal, so the plugin falls back to its configured prompt.

use std::io::{self, Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [identities, file] = args.as_slice() else {
        eprintln!("usage: age_decrypt <identities-file> <encrypted-file>");
        return ExitCode::from(2);
    };
    match run(identities, file) {
        Ok(plain) => {
            io::stdout().write_all(&plain).unwrap();
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("age_decrypt: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(identities: &str, file: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(identities)?;
    let ids: Vec<age::plugin::Identity> =
        text.lines().filter(|l| l.starts_with("AGE-PLUGIN-")).map(|l| l.parse()).collect::<Result<_, _>>()?;
    let plugin = age::plugin::IdentityPluginV1::new("agent", &ids, age::NoCallbacks)?;
    let ct = std::fs::read(file)?;
    let mut r = age::Decryptor::new(ct.as_slice())?.decrypt(std::iter::once(&plugin as &dyn age::Identity))?;
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}
