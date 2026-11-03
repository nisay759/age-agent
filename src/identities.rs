//! Reading at-rest identity files, plain or passphrase-encrypted.

use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, x25519};
use zeroize::Zeroizing;

use crate::stub::{self, Ref};

const ENCRYPTED_MAGIC: &[u8] = b"age-encryption.org/";
const ARMOR_MAGIC: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE";

pub struct Loaded {
    pub reference: Ref,
    pub recipient: String,
    pub identity: x25519::Identity,
}

#[derive(Debug)]
pub enum LoadError {
    BadPassphrase,
    Other(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::BadPassphrase => f.write_str("wrong passphrase"),
            LoadError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for LoadError {}

/// The text of an identity file, decrypted when needed. Zeroized on drop.
pub type Plaintext = Zeroizing<Vec<u8>>;

/// Whether the file needs a passphrase. A plain identity file needs none.
pub fn is_encrypted(path: &Path) -> io::Result<bool> {
    let mut head = Vec::new();
    std::fs::File::open(path)?.take(ARMOR_MAGIC.len() as u64).read_to_end(&mut head)?;
    Ok(head.starts_with(ENCRYPTED_MAGIC) || head.starts_with(ARMOR_MAGIC))
}

/// Reads and, when needed, decrypts an identity file. The passphrase is only used here.
pub fn read(path: &Path, passphrase: Option<&SecretString>) -> Result<Plaintext, LoadError> {
    let other = |e: &dyn std::fmt::Display| LoadError::Other(format!("{}: {e}", path.display()));
    let data = std::fs::read(path).map_err(|e| other(&e))?;
    if !(data.starts_with(ENCRYPTED_MAGIC) || data.starts_with(ARMOR_MAGIC)) {
        return Ok(Zeroizing::new(data));
    }
    let pass = passphrase.ok_or_else(|| other(&"identity file is encrypted"))?;
    let reader = age::armor::ArmoredReader::new(data.as_slice());
    let decryptor = Decryptor::new(reader).map_err(|e| other(&e))?;
    let scrypt = age::scrypt::Identity::new(SecretString::from(pass.expose_secret().to_owned()));
    let mut stream = decryptor
        .decrypt(std::iter::once(&scrypt as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed | age::DecryptError::KeyDecryptionFailed => LoadError::BadPassphrase,
            e => other(&e),
        })?;
    // Sized up front: the plaintext is always shorter than the ciphertext, so `read_to_end`
    // never grows the buffer and leaves no partial copy of the decrypted text behind.
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    stream.read_to_end(&mut out).map_err(|e| other(&e))?;
    Ok(out)
}

fn identity_lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split(|&b| b == b'\n').map(|l| l.trim_ascii()).filter(|l| !l.is_empty() && !l.starts_with(b"#"))
}

/// How many identities `parse_into` would push for this text.
pub fn count(text: &[u8]) -> usize {
    identity_lines(text).count()
}

/// Parses every identity line into `out`. The caller sizes `out` with `count` first: a
/// reallocation would move the identities and leave an unzeroized copy in the freed buffer.
pub fn parse_into(text: &[u8], out: &mut Vec<Loaded>) -> io::Result<()> {
    let bad = |e: &dyn std::fmt::Display| io::Error::new(io::ErrorKind::InvalidData, format!("unsupported identity line: {e}"));
    for line in identity_lines(text) {
        let line = std::str::from_utf8(line).map_err(|e| bad(&e))?;
        let identity = x25519::Identity::from_str(line).map_err(|e| bad(&e))?;
        let recipient = identity.to_public().to_string();
        out.push(Loaded { reference: stub::reference(&recipient), recipient, identity });
    }
    Ok(())
}

/// Decrypts (when needed) and parses one identity file.
pub fn load(path: &Path, passphrase: Option<&SecretString>) -> Result<Vec<Loaded>, LoadError> {
    load_all(std::slice::from_ref(&path.to_path_buf()), passphrase)
}

/// Loads every file into one exactly-sized allocation that is never grown, shrunk or moved
/// afterwards, so the only heap copy of each identity is the one the daemon locks and
/// zeroizes (SEC-1). Stack frames used while parsing are scrubbed before returning.
pub fn load_all(paths: &[std::path::PathBuf], passphrase: Option<&SecretString>) -> Result<Vec<Loaded>, LoadError> {
    let mut texts = Vec::with_capacity(paths.len());
    for path in paths {
        texts.push((path, read(path, passphrase)?));
    }
    let mut out = Vec::with_capacity(texts.iter().map(|(_, t)| count(t)).sum());
    for (path, text) in &texts {
        parse_into(text, &mut out).map_err(|e| LoadError::Other(format!("{}: {e}", path.display())))?;
    }
    drop(texts);
    crate::sys::stack_zero();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("age-agent-test-{}-{name}", std::process::id()));
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn plain_and_encrypted() {
        let id = x25519::Identity::generate();
        let secret = id.to_string();
        let text = format!("# created: now\n{}\n", secret.expose_secret());

        let plain = tmp("plain", text.as_bytes());
        assert!(!is_encrypted(&plain).unwrap());
        let got = load(&plain, None).unwrap();
        assert_eq!(got[0].recipient, id.to_public().to_string());

        let enc = {
            let e = age::Encryptor::with_user_passphrase(SecretString::from("hunter2".to_owned()));
            let mut buf = Vec::new();
            let mut w = e.wrap_output(&mut buf).unwrap();
            w.write_all(text.as_bytes()).unwrap();
            w.finish().unwrap();
            tmp("enc", &buf)
        };
        assert!(is_encrypted(&enc).unwrap());
        let good = SecretString::from("hunter2".to_owned());
        let bad = SecretString::from("nope".to_owned());
        assert_eq!(load(&enc, Some(&good)).unwrap().len(), 1);
        assert!(matches!(load(&enc, Some(&bad)), Err(LoadError::BadPassphrase)));
        assert!(matches!(load(&enc, None), Err(LoadError::Other(_))));

        // A plain file never needs the passphrase, so a mixed set loads with one allocation.
        let all = load_all(&[plain.clone(), enc.clone()], Some(&good)).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all.capacity(), 2);
        let _ = std::fs::remove_file(plain);
        let _ = std::fs::remove_file(enc);
    }

    #[test]
    fn count_matches_parse() {
        let a = x25519::Identity::generate().to_string();
        let b = x25519::Identity::generate().to_string();
        let text = format!("# c\n\n  {}\r\n{}\n# tail", a.expose_secret(), b.expose_secret());
        assert_eq!(count(text.as_bytes()), 2);
        let mut out = Vec::with_capacity(count(text.as_bytes()));
        parse_into(text.as_bytes(), &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert!(parse_into(b"AGE-SECRET-KEY-1NOPE\n", &mut out).is_err());
    }
}
