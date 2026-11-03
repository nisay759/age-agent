//! Socket message parser (SEC-6): any byte stream, read as a sequence of frames, must never
//! panic, never allocate past MAX_MESSAGE, and every accepted frame must parse or be rejected.
#![no_main]

use age_agent::protocol::{self, MAX_MESSAGE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    while let Ok(frame) = protocol::read_frame(&mut input) {
        assert!(frame.len() <= MAX_MESSAGE);
        let _ = protocol::parse_request(&frame);
    }
    // The payload alone, as if it had arrived in a well-formed frame.
    let _ = protocol::parse_request(data);
});
