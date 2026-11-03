//! Stub decoder: arbitrary strings and raw payloads must never panic, and anything accepted
//! must re-encode to a stub naming the same reference.
#![no_main]

use age_agent::stub;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = stub::decode_payload(data) {
        assert_eq!(data.len(), 1 + stub::REF_LEN);
        assert_eq!(stub::decode(&stub::encode(&r)), Ok(r));
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(r) = stub::decode(s) {
            assert_eq!(stub::decode(&stub::encode(&r)), Ok(r));
        }
        if let Some(r) = stub::ref_from_hex(s) {
            assert_eq!(stub::ref_hex(&r), s.to_ascii_lowercase());
        }
    }
});
