//! Encryption must not silently drop a recipient whose certificate has no
//! usable encryption key (audit N1). Fixtures in `fixtures/recipients` were
//! made with GnuPG: alice has a valid X25519 subkey; bob's expired; erin's is
//! revoked; dave has none. Their primary keys are valid.

use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Cert;

const ALICE: &[u8] = include_bytes!("fixtures/recipients/alice.asc");
const BOB_EXPIRED: &[u8] = include_bytes!("fixtures/recipients/bob.asc");
const ERIN_REVOKED: &[u8] = include_bytes!("fixtures/recipients/erin.asc");
const DAVE_NO_SUBKEY: &[u8] = include_bytes!("fixtures/recipients/dave.asc");

fn pgp() -> SequoiaOpenPgp {
    SequoiaOpenPgp::new()
}

fn armored() -> EncryptOptions {
    EncryptOptions { armored: true }
}

fn fingerprint(cert: &[u8]) -> String {
    Cert::from_bytes(cert).unwrap().fingerprint().to_hex()
}

fn gen(userid: &str, profile: KeyProfile) -> GeneratedKey {
    pgp()
        .generate_key(&GenerateKeyOptions {
            userid: userid.into(),
            passphrase: None,
            profile,
        })
        .expect("generate")
}

fn expect_unusable(result: Result<Vec<u8>>, index: usize, cert: &[u8]) {
    let err = result.expect_err("must not encrypt");
    assert_eq!(err.code(), 6, "same category as no suitable encryption key");
    assert_eq!(
        err,
        OpenPgpError::RecipientWithoutEncryptionKey {
            index,
            fingerprint: fingerprint(cert),
        }
    );
    // secMail parses this text to name the recipient.
    assert_eq!(
        err.to_string(),
        format!(
            "no suitable encryption key for recipient {index} ({})",
            fingerprint(cert)
        )
    );
}

#[test]
fn valid_recipient_plus_expired_subkey_fails() {
    expect_unusable(
        pgp().encrypt(b"n1", &[ALICE, BOB_EXPIRED], &armored()),
        1,
        BOB_EXPIRED,
    );
}

#[test]
fn valid_recipient_plus_revoked_subkey_fails() {
    expect_unusable(
        pgp().encrypt(b"n1", &[ALICE, ERIN_REVOKED], &armored()),
        1,
        ERIN_REVOKED,
    );
}

#[test]
fn valid_recipient_plus_no_encryption_subkey_fails() {
    expect_unusable(
        pgp().encrypt(b"n1", &[ALICE, DAVE_NO_SUBKEY], &armored()),
        1,
        DAVE_NO_SUBKEY,
    );
}

#[test]
fn first_unusable_certificate_is_reported_by_position() {
    expect_unusable(
        pgp().encrypt(b"n1", &[ERIN_REVOKED, ALICE, BOB_EXPIRED], &armored()),
        0,
        ERIN_REVOKED,
    );
}

#[test]
fn single_unusable_recipient_fails() {
    expect_unusable(
        pgp().encrypt(b"n1", &[BOB_EXPIRED], &armored()),
        0,
        BOB_EXPIRED,
    );
}

/// One intended recipient plus the sender's valid Sent-copy key: the shape
/// compose uses for every message.
#[test]
fn intended_recipient_plus_valid_sent_copy_key_fails() {
    let sender = gen("Sender <sender@example.test>", KeyProfile::ClassicalCv25519);
    expect_unusable(
        pgp().encrypt(b"n1", &[BOB_EXPIRED, &sender.public], &armored()),
        0,
        BOB_EXPIRED,
    );
}

#[test]
fn encrypt_and_sign_also_fails() {
    let sender = gen("Sender <sender@example.test>", KeyProfile::ClassicalCv25519);
    let err = pgp()
        .encrypt_and_sign(
            b"n1",
            &[ERIN_REVOKED, &sender.public],
            &sender.secret,
            None,
            &armored(),
        )
        .expect_err("must not encrypt");
    assert_eq!(err.code(), 6);
    assert!(matches!(
        err,
        OpenPgpError::RecipientWithoutEncryptionKey { index: 0, .. }
    ));
}

#[test]
fn valid_classical_and_hybrid_recipients_can_all_decrypt() {
    let classical = gen("Classical <c@example.test>", KeyProfile::ClassicalCv25519);
    let v6 = gen("V6 <v6@example.test>", KeyProfile::Rfc9580Cv25519);
    let hybrid = gen("Hybrid <pq@example.test>", KeyProfile::Rfc9980MlDsa65);
    let sender = gen("Sender <sender@example.test>", KeyProfile::ClassicalCv25519);
    let ct = pgp()
        .encrypt(
            b"all of you",
            &[
                &classical.public,
                &v6.public,
                &hybrid.public,
                &sender.public,
            ],
            &armored(),
        )
        .expect("encrypt to valid recipients");
    for key in [&classical, &v6, &hybrid, &sender] {
        let pt = pgp().decrypt(&ct, &key.secret, None).expect("decrypt");
        assert_eq!(pt.plaintext, b"all of you");
    }
}

#[test]
fn valid_fixture_recipient_still_encrypts() {
    pgp()
        .encrypt(b"n1", &[ALICE], &armored())
        .expect("alice has a live encryption subkey");
}
