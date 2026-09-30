//! RFC 9980 Appendix A. Armor fixtures are extracted from the published RFC.

use std::fs;
use std::path::PathBuf;

use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rfc9980")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn pgp() -> SequoiaOpenPgp {
    SequoiaOpenPgp::new()
}

fn decrypt_expect(secret: &str, message: &str) {
    let p = pgp();
    let pt = p
        .decrypt(&fixture(message), &fixture(secret), None)
        .unwrap_or_else(|e| panic!("decrypt {message}: {e:?}"));
    assert_eq!(pt.plaintext, b"Testing\n", "{message}");
}

fn pubkey_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../pubkey")
}

fn node_encrypt(public_name: &str, nonce: &[u8]) -> Vec<u8> {
    let dir = std::env::temp_dir();
    let out = dir.join(format!("scomm-rfc9980-{}.bin", public_name.replace('.', "-")));
    let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let pub_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rfc9980")
        .join(public_name);
    let status = std::process::Command::new("node")
        .current_dir(pubkey_dir())
        .args([
            "--import",
            "./scripts/registerTsResolve.js",
            "scripts/openpgpChallengeCli.ts",
            pub_path.to_str().unwrap(),
            &nonce_hex,
            out.to_str().unwrap(),
        ])
        .status()
        .expect("node");
    assert!(status.success(), "server encoder failed for {public_name}");
    fs::read(&out).unwrap()
}

#[test]
fn server_encoder_messages_decrypt_in_sequoia() {
    let nonce = b"0123456789abcdef0123456789abcdef";
    let v6 = node_encrypt("A-1-2.asc", nonce);
    let pt = pgp()
        .decrypt(&v6, &fixture("A-1-1.asc"), None)
        .expect("v6 decrypt");
    assert_eq!(pt.plaintext, nonce);
    let v4 = node_encrypt("A-2-2.asc", nonce);
    let pt = pgp()
        .decrypt(&v4, &fixture("A-2-1.asc"), None)
        .expect("v4 decrypt");
    assert_eq!(pt.plaintext, nonce);
}

#[test]
fn server_verifier_accepts_sign_pop() {
    let p = pgp();
    if !p.rfc9980_ready() {
        return;
    }
    let key = p
        .generate_key(&GenerateKeyOptions {
            userid: "Pop <pop@example.com>".into(),
            passphrase: None,
            profile: KeyProfile::Rfc9980MlDsa65,
        })
        .expect("generate");
    let message = b"artifact-pop";
    let signature = p
        .sign_pop(&message[..], &key.secret, None, "scomm-pop@scomm.ai")
        .expect("sign_pop");
    let dir = std::env::temp_dir();
    let pub_path = dir.join("scomm-pop-pub.bin");
    let msg_path = dir.join("scomm-pop-msg.bin");
    let sig_path = dir.join("scomm-pop-sig.bin");
    fs::write(&pub_path, &key.public).unwrap();
    fs::write(&msg_path, message).unwrap();
    fs::write(&sig_path, &signature).unwrap();
    let status = std::process::Command::new("node")
        .current_dir(pubkey_dir())
        .args([
            "--import",
            "./scripts/registerTsResolve.js",
            "scripts/openpgpChallengeCli.ts",
            "verify",
            pub_path.to_str().unwrap(),
            msg_path.to_str().unwrap(),
            sig_path.to_str().unwrap(),
        ])
        .status()
        .expect("node");
    assert!(status.success(), "server rejected sign_pop");
}

fn verify_expect(public: &str, signature: &str) {
    let p = pgp();
    let result = p
        .verify(b"Testing\n", &fixture(signature), &fixture(public))
        .unwrap_or_else(|e| panic!("verify {signature}: {e:?}"));
    assert_eq!(
        result.validity,
        SignatureValidity::CryptographicallyValid,
        "{signature}"
    );
}

#[test]
fn appendix_a1_a3_import_decrypt_and_detached_verify() {
    for (secret, public) in [("A-1-1.asc", "A-1-2.asc"), ("A-2-1.asc", "A-2-2.asc"), ("A-3-1.asc", "A-3-2.asc")] {
        let info = pgp().inspect_key(&fixture(secret)).expect(secret);
        assert!(!info.fingerprint.0.is_empty(), "{secret}");
        let _ = public;
    }
    decrypt_expect("A-1-1.asc", "A-1-3.asc");
    decrypt_expect("A-2-1.asc", "A-2-3.asc");
    decrypt_expect("A-2-1.asc", "A-2-4.asc");
    decrypt_expect("A-3-1.asc", "A-3-3.asc");
    verify_expect("A-3-2.asc", "A-3-4.asc");
}

#[test]
fn appendix_a4_a7_decrypt_and_verify_only() {
    decrypt_expect("A-4-1.asc", "A-4-3.asc");
    decrypt_expect("A-5-1.asc", "A-5-3.asc");
    verify_expect("A-4-2.asc", "A-4-4.asc");
    verify_expect("A-5-2.asc", "A-5-4.asc");
    verify_expect("A-6-2.asc", "A-6-3.asc");
    verify_expect("A-7-2.asc", "A-7-3.asc");
}
