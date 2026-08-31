use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;

fn pgp() -> SequoiaOpenPgp {
    SequoiaOpenPgp::new()
}

fn gen(userid: &str) -> GeneratedKey {
    pgp()
        .generate_key(&GenerateKeyOptions {
            userid: userid.into(),
            passphrase: None,
            profile: KeyProfile::ClassicalCv25519,
        })
        .expect("generate")
}

#[test]
fn generate_inspect_export() {
    let key = gen("Alice <alice@example.com>");
    assert!(!key.public.is_empty());
    assert!(!key.secret.is_empty());
    assert!(key.info.has_secret);
    assert!(!key.info.fingerprint.0.is_empty());
    assert!(key.info.identities.iter().any(|i| {
        i.email.as_deref() == Some("alice@example.com")
    }));
    assert!(key
        .info
        .capabilities
        .contains(&OpenPgpKeyUsage::Encryption));
    assert!(key.info.capabilities.contains(&OpenPgpKeyUsage::Signing));

    let pub_info = pgp().inspect_key(&key.public).unwrap();
    assert!(!pub_info.has_secret);
    assert!(!pub_info.subkeys.is_empty());
    assert_eq!(pub_info.fingerprint, key.info.fingerprint);

    let exported = pgp().export_public_key(&key.secret).unwrap();
    let again = pgp().inspect_key(&exported).unwrap();
    assert_eq!(again.fingerprint, key.info.fingerprint);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let alice = gen("Alice <alice@example.com>");
    let bob = gen("Bob <bob@example.com>");
    let p = pgp();
    let ct = p
        .encrypt(
            b"hello scomm",
            &[&alice.public, &bob.public],
            &EncryptOptions { armored: false },
        )
        .unwrap();
    let info = p.inspect_message(&ct).unwrap();
    assert!(info.encrypted);
    assert!(!info.recipient_key_ids.is_empty());

    let pt_a = p.decrypt(&ct, &alice.secret, None).unwrap();
    let pt_b = p.decrypt(&ct, &bob.secret, None).unwrap();
    assert_eq!(pt_a.plaintext, b"hello scomm");
    assert_eq!(pt_b.plaintext, b"hello scomm");
}

#[test]
fn wrong_recipient_fails() {
    let alice = gen("Alice <alice@example.com>");
    let mallory = gen("Mallory <mallory@example.com>");
    let p = pgp();
    let ct = p
        .encrypt(b"secret", &[&alice.public], &EncryptOptions::default())
        .unwrap();
    let err = p.decrypt(&ct, &mallory.secret, None).unwrap_err();
    assert!(
        matches!(
            err,
            OpenPgpError::DecryptionFailed | OpenPgpError::WrongPrivateKey
        ),
        "{err:?}"
    );
}

#[test]
fn detached_sign_verify() {
    let alice = gen("Alice <alice@example.com>");
    let p = pgp();
    let data = b"signed body";
    let sig = p
        .sign(
            data,
            &alice.secret,
            None,
            &SignOptions {
                armored: false,
                detached: true,
            },
        )
        .unwrap();
    let v = p.verify(data, &sig.bytes, &alice.public).unwrap();
    assert_eq!(v.validity, SignatureValidity::CryptographicallyValid);
    assert_eq!(v.signer_fingerprint.as_ref(), Some(&sig.fingerprint));

    let mut bad = data.to_vec();
    bad[0] ^= 1;
    let v2 = p.verify(&bad, &sig.bytes, &alice.public).unwrap();
    assert_ne!(v2.validity, SignatureValidity::CryptographicallyValid);
}

#[test]
fn encrypt_and_sign_decrypt_and_verify() {
    let alice = gen("Alice <alice@example.com>");
    let bob = gen("Bob <bob@example.com>");
    let p = pgp();
    let ct = p
        .encrypt_and_sign(
            b"from alice",
            &[&bob.public],
            &alice.secret,
            None,
            &EncryptOptions::default(),
        )
        .unwrap();
    let out = p
        .decrypt_and_verify(&ct, &bob.secret, None, &[&alice.public])
        .unwrap();
    assert_eq!(out.plaintext, b"from alice");
    assert!(out
        .signatures
        .iter()
        .any(|s| s.validity == SignatureValidity::CryptographicallyValid));
}

#[test]
fn armor_roundtrip_public_key() {
    let alice = gen("Alice <alice@example.com>");
    let p = pgp();
    let armored = p.armor(ArmorKind::PublicKey, &alice.public).unwrap();
    assert!(std::str::from_utf8(&armored)
        .unwrap()
        .contains("BEGIN PGP PUBLIC KEY"));
    let bin = p.dearmor(&armored).unwrap();
    assert_eq!(
        p.inspect_key(&bin).unwrap().fingerprint,
        alice.info.fingerprint
    );
}

#[test]
fn passphrase_protected_decrypt() {
    let p = pgp();
    let key = p
        .generate_key(&GenerateKeyOptions {
            userid: "Locked <locked@example.com>".into(),
            passphrase: Some("correct-horse".into()),
            profile: KeyProfile::ClassicalCv25519,
        })
        .unwrap();
    let ct = p
        .encrypt(b"locked", &[&key.public], &EncryptOptions::default())
        .unwrap();
    assert!(p.decrypt(&ct, &key.secret, None).is_err());
    let pt = p.decrypt(&ct, &key.secret, Some("correct-horse")).unwrap();
    assert_eq!(pt.plaintext, b"locked");
    assert!(p.test_passphrase(&key.secret, None).is_err());
    p.test_passphrase(&key.secret, Some("correct-horse"))
        .unwrap();
}
