//! No file under the user's home or runtime dir may ever contain the identity or passphrase.
//! Runs a whole session through the real plugin while a polling watcher scans both trees.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, fs, thread};

use common::*;

fn scan(roots: &[std::path::PathBuf], needles: &[Vec<u8>], hits: &Mutex<Vec<String>>) {
    for r in roots {
        walk(r, &mut |p| {
            // Sockets and fifos are skipped by `walk`; unreadable files can't hold anything we read.
            let Ok(data) = fs::read(p) else { return };
            for n in needles {
                if data.windows(n.len()).any(|w| w == n.as_slice()) {
                    hits.lock().unwrap().push(p.display().to_string());
                }
            }
        });
    }
}

#[test]
fn nothing_secret_ever_touches_disk() {
    let e = Env::new("sec-plaintext");
    let bin_dir = std::path::Path::new(AGE_AGENT).parent().unwrap().to_owned();
    // SAFETY: the only test in this binary, so no other thread touches the environment.
    unsafe {
        env::set_var("HOME", &e.home);
        env::set_var("XDG_CONFIG_HOME", &e.cfg_home);
        env::set_var("XDG_RUNTIME_DIR", &e.run);
        env::set_var("PATH", format!("{}:{}", bin_dir.display(), env::var("PATH").unwrap()));
    }

    // The at-rest file legitimately holds the (encrypted) key; the needles are plaintext forms.
    let needles = vec![e.secret_key.clone().into_bytes(), PASSPHRASE.as_bytes().to_vec(), b"AGE-SECRET-KEY-1".to_vec()];
    let roots = vec![e.home.clone(), e.run.clone()];
    let hits = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (roots, needles, hits, stop) = (roots.clone(), needles.clone(), hits.clone(), stop.clone());
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                scan(&roots, &needles, &hits);
                thread::sleep(Duration::from_millis(10));
            }
        })
    };

    let ct = e.ciphertext(b"payload");
    // Auto-start, pinentry unlock, repeated use, lock, re-unlock, wrong passphrase, stop.
    assert_eq!(decrypt_via_plugin(&e.stub, &ct).unwrap(), b"payload");
    for _ in 0..5 {
        decrypt_via_plugin(&e.stub, &ct).unwrap();
    }
    let mut c = e.connect();
    c.lock().unwrap();
    decrypt_via_plugin(&e.stub, &ct).unwrap();
    c.lock().unwrap();
    fs::write(&e.pass_file, "wrong").unwrap();
    assert!(decrypt_via_plugin(&e.stub, &ct).is_err());
    fs::write(&e.pass_file, PASSPHRASE).unwrap();
    decrypt_via_plugin(&e.stub, &ct).unwrap();
    c.stop().unwrap();
    thread::sleep(Duration::from_millis(300));

    stop.store(true, Ordering::Relaxed);
    watcher.join().unwrap();
    scan(&roots, &needles, &hits); // final sweep
    let hits = hits.lock().unwrap();
    // Only the legitimately encrypted identity file may be named, and it must not match plaintext needles.
    assert!(hits.is_empty(), "plaintext secret found in: {hits:?}");
}
