//! Audit B1 (2026-11-11): a truncated message must fail, never kill the app.
//! Sequoia 2.4.1 panics on some cut points, so the FFI's `catch_unwind` is
//! the guard, and it only works if the release build unwinds.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn release_profile_unwinds_so_ffi_can_catch_panics() {
    let toml = fs::read_to_string(root().join("../../Cargo.toml")).unwrap();
    let release = toml.split("[profile.release]").nth(1).expect("release profile");
    let release = release.split("\n[").next().unwrap();
    assert!(
        !release.contains("panic = \"abort\""),
        "panic = \"abort\" makes a Sequoia panic abort the app"
    );
}

#[test]
fn every_truncation_fails_without_plaintext() {
    // GnuPG's SEIPDv1 messages are the ones the audit saw panic.
    let cases = [
        ("scomm", "v4", "v4.pgp"),
        ("scomm", "v6", "v6.pgp"),
        ("scomm", "rfc9980", "rfc9980.pgp"),
        ("gnupg", "ed25519", "ed25519.default.pgp"),
        ("gnupg", "nistp256", "nistp256.default.pgp"),
        ("gnupg", "nistp256", "nistp256.uncompressed.pgp"),
    ];
    for (set, name, file) in cases {
        let dir = root().join("tests/fixtures").join(set);
        let msg = fs::read(dir.join(file)).unwrap();
        let key = fs::read(dir.join(format!("{name}.sec"))).unwrap();
        let mut panics = 0;
        for n in 1..msg.len() {
            let r = catch_unwind(AssertUnwindSafe(|| {
                SequoiaOpenPgp::new().decrypt(&msg[..n], &key, None)
            }));
            match r {
                Err(_) => panics += 1, // caught, as the FFI does
                Ok(Ok(_)) => panic!("{file}: cut at {n} of {} decrypted", msg.len()),
                Ok(Err(_)) => {}
            }
        }
        eprintln!("{file}: {panics} of {} cuts panicked (caught)", msg.len() - 1);
    }
}
