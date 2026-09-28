//! Records and checks proof-of-possession fixtures from the pre-OpenSSL build.
//!
//! The first run writes `tests/fixtures/pop.json`. Later runs load that file
//! and require the same signatures and shared secret.

use std::fs;
use std::path::PathBuf;

use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pop.json")
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | bytes[i + 2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    if i < bytes.len() {
        let mut n = (bytes[i] as u32) << 16;
        out.push(T[((n >> 18) & 63) as usize] as char);
        if i + 1 < bytes.len() {
            n |= (bytes[i + 1] as u32) << 8;
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
    }
    out
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[test]
fn pop_fixtures_match_recorded_outputs() {
    let path = fixture_path();
    let p = SequoiaOpenPgp::new();
    let message = b"scomm-pop-fixture-v1";
    let kem_ct = vec![0x11u8; 1088];
    let eph = vec![0x22u8; 32];

    if !path.exists() {
        let key = p
            .generate_key(&GenerateKeyOptions {
                userid: "Fixture <fixture@scomm.ai>".into(),
                passphrase: None,
                profile: KeyProfile::Rfc9980MlDsa65,
            })
            .expect("generate rfc9980 key");
        let (ml, ed) = p
            .pop_sign_composite(message, &key.secret, None)
            .expect("pop sign");
        let shared = p
            .pop_hybrid_shared(&key.secret, None, &kem_ct, &eph)
            .expect("pop shared");
        let classical = p
            .generate_key(&GenerateKeyOptions {
                userid: "Classical <classical@scomm.ai>".into(),
                passphrase: None,
                profile: KeyProfile::ClassicalCv25519,
            })
            .expect("generate classical");
        let ct = p
            .encrypt(b"hello fixtures", &[&classical.public], &EncryptOptions { armored: false })
            .expect("encrypt");
        let body = format!(
            "{{\n  \"message_b64\": {},\n  \"kem_ciphertext_b64\": {},\n  \"ephemeral_x25519_b64\": {},\n  \"secret_b64\": {},\n  \"mldsa_sig_b64\": {},\n  \"ed25519_sig_b64\": {},\n  \"shared_b64\": {},\n  \"classical_secret_b64\": {},\n  \"classical_public_b64\": {},\n  \"classical_ciphertext_b64\": {},\n  \"classical_plaintext_b64\": {}\n}}\n",
            json_str(&b64(message)),
            json_str(&b64(&kem_ct)),
            json_str(&b64(&eph)),
            json_str(&b64(&key.secret)),
            json_str(&b64(&ml)),
            json_str(&b64(&ed)),
            json_str(&b64(&shared)),
            json_str(&b64(&classical.secret)),
            json_str(&b64(&classical.public)),
            json_str(&b64(&ct)),
            json_str(&b64(b"hello fixtures")),
        );
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        return;
    }

    let raw = fs::read_to_string(&path).unwrap();
    let secret = decode_field(&raw, "secret_b64");
    let (ml, ed) = p.pop_sign_composite(message, &secret, None).expect("pop sign");
    assert_eq!(b64(&ml), field(&raw, "mldsa_sig_b64"));
    assert_eq!(b64(&ed), field(&raw, "ed25519_sig_b64"));
    let shared = p
        .pop_hybrid_shared(&secret, None, &kem_ct, &eph)
        .expect("pop shared");
    assert_eq!(b64(&shared), field(&raw, "shared_b64"));
    let classical_secret = decode_field(&raw, "classical_secret_b64");
    let classical_ct = decode_field(&raw, "classical_ciphertext_b64");
    let pt = p.decrypt(&classical_ct, &classical_secret, None).unwrap();
    assert_eq!(pt.plaintext, b"hello fixtures");
}

fn field(raw: &str, name: &str) -> String {
    let key = format!("\"{name}\": \"");
    let start = raw.find(&key).unwrap_or_else(|| panic!("missing {name}")) + key.len();
    let end = raw[start..].find('"').unwrap() + start;
    raw[start..end].to_string()
}

fn decode_field(raw: &str, name: &str) -> Vec<u8> {
    b64_decode(&field(raw, name))
}

fn b64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let n = ((val(bytes[i]) as u32) << 18)
            | ((val(bytes[i + 1]) as u32) << 12)
            | ((val(bytes[i + 2]) as u32) << 6)
            | val(bytes[i + 3]) as u32;
        out.push((n >> 16) as u8);
        if bytes[i + 2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if bytes[i + 3] != b'=' {
            out.push(n as u8);
        }
        i += 4;
    }
    out
}
