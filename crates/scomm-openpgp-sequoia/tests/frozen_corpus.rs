//! Keys and messages written by an earlier build, so an engine or Sequoia upgrade
//! that can no longer read existing mail fails here. Throwaway test material.
//!
//! Add new files with `cargo test --test frozen_corpus -- --ignored`. Existing
//! files are never rewritten: replacing one would hide the failure it guards.

use std::fs;
use std::path::PathBuf;

use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;

const PLAINTEXT: &[u8] = b"Content-Type: text/plain\r\n\r\nfrozen plaintext\r\n";
const PROFILES: [(&str, KeyProfile); 3] = [
    ("v4", KeyProfile::ClassicalCv25519),
    ("v6", KeyProfile::Rfc9580Cv25519),
    ("rfc9980", KeyProfile::Rfc9980MlDsa65),
];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scomm")
}

fn file(name: &str) -> Vec<u8> {
    fs::read(dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn pgp() -> SequoiaOpenPgp {
    SequoiaOpenPgp::new()
}

#[test]
fn frozen_messages_still_open() {
    for (name, _) in PROFILES {
        let secret = file(&format!("{name}.sec"));
        let public = file(&format!("{name}.pub"));
        let out = pgp()
            .decrypt(&file(&format!("{name}.pgp")), &secret, None)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(out.plaintext, PLAINTEXT, "{name}");
        let result = pgp()
            .verify(PLAINTEXT, &file(&format!("{name}.sig")), &public)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(result.validity, SignatureValidity::CryptographicallyValid, "{name}");
    }
    for name in ["v4", "rfc9980"] {
        let out = pgp()
            .decrypt(&file("mixed.pgp"), &file(&format!("{name}.sec")), None)
            .unwrap_or_else(|e| panic!("mixed for {name}: {e:?}"));
        assert_eq!(out.plaintext, PLAINTEXT, "mixed for {name}");
    }
}

fn write_new(name: &str, data: &[u8]) {
    let path = dir().join(name);
    if path.exists() {
        return;
    }
    fs::write(path, data).unwrap();
}

#[test]
#[ignore = "writes fixtures"]
fn add_missing_fixtures() {
    fs::create_dir_all(dir()).unwrap();
    for (name, profile) in PROFILES {
        if !dir().join(format!("{name}.sec")).exists() {
            let key = pgp()
                .generate_key(&GenerateKeyOptions {
                    userid: format!("Frozen {name} <frozen-{name}@example.com>"),
                    passphrase: None,
                    profile,
                })
                .unwrap();
            write_new(&format!("{name}.pub"), &key.public);
            write_new(&format!("{name}.sec"), &key.secret);
        }
        let public = file(&format!("{name}.pub"));
        let secret = file(&format!("{name}.sec"));
        let ct = pgp()
            .encrypt(PLAINTEXT, &[&public], &EncryptOptions::default())
            .unwrap();
        write_new(&format!("{name}.pgp"), &ct);
        let sig = pgp()
            .sign(PLAINTEXT, &secret, None, &SignOptions::default())
            .unwrap();
        write_new(&format!("{name}.sig"), &sig.bytes);
    }
    let (v4, pq) = (file("v4.pub"), file("rfc9980.pub"));
    let ct = pgp()
        .encrypt(PLAINTEXT, &[&pq, &v4], &EncryptOptions::default())
        .unwrap();
    write_new("mixed.pgp", &ct);
}
