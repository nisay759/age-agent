//! SEC-1 regression: after an unlock the only copy of a private key in this process's
//! writable memory is the one inside the locked identity vector, and after a lock there is
//! none. Runs the daemon's exact loading path on a worker thread (like a connection thread)
//! and scans every private writable mapping through `/proc/self/mem`.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::thread;
use std::time::{Duration, Instant};

use age::secrecy::SecretString;
use age_agent::daemon::Session;
use age_agent::identities;

/// A fixed test identity. Both forms are constants in read-only memory, so this harness
/// itself never leaves a copy of the needle in writable memory.
const RAW_KEY: [u8; 32] = [
    0x50, 0x79, 0xa8, 0xc7, 0xb1, 0xd9, 0x7f, 0x8b, 0xf6, 0xf9, 0x44, 0xd4, 0x5d, 0xf6, 0x0f, 0xeb, 0x12, 0x65, 0xfa, 0xb8, 0x73, 0xf2, 0xa0, 0x58, 0x20, 0x0b, 0x32, 0xf2, 0x78, 0x20, 0xc0, 0x7c,
];
const SECRET_LINE: &str = "AGE-SECRET-KEY-12PU633A3M9LCHAHEGN29MAS0AVFXT74CW0E2QKPQPVE0Y7PQCP7QT65ZWP";
const PASSPHRASE: &str = "memory-test-passphrase-3f9c";

const CHUNK: usize = 1 << 20;

struct Scanner {
    buf: Vec<u8>,
    mem: fs::File,
}

impl Scanner {
    fn new() -> Self {
        Self { buf: vec![0; CHUNK], mem: fs::File::open("/proc/self/mem").unwrap() }
    }

    /// Occurrences of `needle` in every private writable mapping: heap, anonymous arenas and
    /// cached worker-thread stacks. The main thread's stack (this harness's frames) and the
    /// scan buffer itself are left out.
    fn count(&mut self, needle: &[u8]) -> usize {
        let maps = fs::read_to_string("/proc/self/maps").unwrap();
        let buf_start = self.buf.as_ptr() as usize;
        let buf_end = buf_start + self.buf.len();
        let mut hits = 0;
        for line in maps.lines() {
            let mut it = line.split_whitespace();
            let (range, perms) = (it.next().unwrap(), it.next().unwrap());
            let name = it.nth(3).unwrap_or("");
            if !perms.starts_with("rw") || perms.ends_with('s') || name == "[stack]" || name.starts_with("[v") {
                continue;
            }
            let (a, b) = range.split_once('-').unwrap();
            let (start, end) = (usize::from_str_radix(a, 16).unwrap(), usize::from_str_radix(b, 16).unwrap());
            let (mut pos, mut carry) = (start, 0usize);
            while pos < end {
                let n = (end - pos).min(CHUNK - carry);
                if self.mem.seek(SeekFrom::Start(pos as u64)).is_err() || self.mem.read_exact(&mut self.buf[carry..carry + n]).is_err() {
                    break; // a guard page or an unreadable mapping
                }
                let (filled, base) = (carry + n, pos - carry);
                for (i, w) in self.buf[..filled].windows(needle.len()).enumerate() {
                    let addr = base + i;
                    if w == needle && !(buf_start..buf_end).contains(&addr) {
                        hits += 1;
                    }
                }
                pos += n;
                // Keep the tail so a needle straddling two chunks is still found.
                carry = (needle.len() - 1).min(filled);
                self.buf.copy_within(filled - carry..filled, 0);
            }
        }
        hits
    }
}

#[test]
fn only_the_locked_vector_holds_the_key() {
    let dir = std::env::temp_dir().join(format!("age-agent-memory-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("identities");
    {
        let e = age::Encryptor::with_user_passphrase(SecretString::from(PASSPHRASE));
        let mut buf = Vec::new();
        let mut w = e.wrap_output(&mut buf).unwrap();
        w.write_all(b"# created: by tests/memory.rs\n").unwrap();
        w.write_all(SECRET_LINE.as_bytes()).unwrap();
        w.write_all(b"\n").unwrap();
        w.finish().unwrap();
        fs::write(&path, buf).unwrap();
    }
    let mut sc = Scanner::new();
    // The encryptor above buffered the plaintext; whatever it left is this harness's noise,
    // measured here so only the daemon path's additions are judged below.
    let line_before = sc.count(SECRET_LINE.as_bytes());
    assert_eq!(sc.count(&RAW_KEY), 0, "harness left a raw key copy before any age-agent code ran");

    // Exactly what Daemon::unlock does, on a thread of its own like a connection thread.
    let session = thread::spawn({
        let path = path.clone();
        move || {
            let pass = SecretString::from(PASSPHRASE);
            let all = identities::load_all(&[path], Some(&pass)).unwrap();
            assert_eq!(all.len(), 1);
            Session::new(all, Instant::now(), Duration::from_secs(900), Duration::from_secs(28800))
        }
    })
    .join()
    .unwrap();

    assert_eq!(sc.count(&RAW_KEY), 1, "while unlocked, the raw key must exist only in the locked vector");
    assert!(sc.count(SECRET_LINE.as_bytes()) <= line_before, "the decrypted identity text was left in memory");
    assert_eq!(sc.count(PASSPHRASE.as_bytes()), 0, "the passphrase was left in memory after the unlock");

    drop(session);
    assert_eq!(sc.count(&RAW_KEY), 0, "a copy of the raw key survived the lock");
    assert!(sc.count(SECRET_LINE.as_bytes()) <= line_before);
    assert_eq!(sc.count(PASSPHRASE.as_bytes()), 0);
    let _ = fs::remove_dir_all(&dir);
}
