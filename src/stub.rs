//! Plugin identity stubs: `AGE-PLUGIN-AGENT-1…` naming an identity without containing it.

use bech32::{Bech32, Hrp};
use sha2::{Digest, Sha256};

const HRP: &str = "age-plugin-agent-";
const VERSION: u8 = 0x01;
pub const REF_LEN: usize = 16;

pub type Ref = [u8; REF_LEN];

/// The first 16 bytes of SHA-256 over the recipient string.
pub fn reference(recipient: &str) -> Ref {
    let digest = Sha256::digest(recipient.as_bytes());
    digest[..REF_LEN].try_into().expect("digest is longer than REF_LEN")
}

pub fn encode(r: &Ref) -> String {
    let mut payload = vec![VERSION];
    payload.extend_from_slice(r);
    let hrp = Hrp::parse(HRP).expect("constant HRP is valid");
    bech32::encode::<Bech32>(hrp, &payload).expect("stub fits in a bech32 string").to_uppercase()
}

/// Decodes the raw payload that age hands to `add_identity`.
pub fn decode_payload(payload: &[u8]) -> Result<Ref, String> {
    match payload {
        [VERSION, rest @ ..] => rest.try_into().map_err(|_| "stub reference has the wrong length".into()),
        [v, ..] => Err(format!("unsupported stub version {v}")),
        [] => Err("empty stub".into()),
    }
}

/// Decodes a full `AGE-PLUGIN-AGENT-1…` string.
pub fn decode(s: &str) -> Result<Ref, String> {
    let (hrp, payload) = bech32::decode(s).map_err(|e| e.to_string())?;
    if !hrp.as_str().eq_ignore_ascii_case(HRP) {
        return Err(format!("unexpected prefix {hrp}"));
    }
    decode_payload(&payload)
}

pub fn ref_hex(r: &Ref) -> String {
    r.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn ref_from_hex(s: &str) -> Option<Ref> {
    // Hex digits only: `from_str_radix` alone would also accept a leading `+`.
    if s.len() != REF_LEN * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0; REF_LEN];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let r = reference("age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq");
        let s = encode(&r);
        assert!(s.starts_with("AGE-PLUGIN-AGENT-1"));
        assert_eq!(decode(&s).unwrap(), r);
        assert_eq!(decode(&s.to_lowercase()).unwrap(), r);
        assert_eq!(ref_from_hex(&ref_hex(&r)), Some(r));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("AGE-PLUGIN-AGENT-1QQ").is_err());
        assert!(decode_payload(&[2; 17]).is_err());
        assert!(decode_payload(&[1, 0, 0]).is_err());
        assert!(decode_payload(&[]).is_err());
        assert!(ref_from_hex("zz").is_none());
        // Found by fuzz/stub: "+2" used to parse as 0x02.
        assert!(ref_from_hex(&"+0".repeat(REF_LEN)).is_none());
    }
}
