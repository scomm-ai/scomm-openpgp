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
    assert!(!key.info.is_pqc());
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

#[test]
fn rfc9980_generate_encrypt_sign_when_supported() {
    let p = pgp();
    if !p.rfc9980_ready() {
        return;
    }
    let key = p
        .generate_key(&GenerateKeyOptions {
            userid: "Pqc <pqc@example.com>".into(),
            passphrase: None,
            profile: KeyProfile::Rfc9980MlDsa65,
        })
        .expect("rfc9980 generate");
    assert!(key.info.is_pqc(), "expected PQC catalog/ids: {:?}", key.info);
    assert!(key.info.is_pqc_signing());
    assert_eq!(key.info.algorithm_id, 30);
    assert!(
        key.info
            .subkeys
            .iter()
            .any(|s| s.algorithm_id == 35 || s.algorithm.contains("mlkem")),
        "expected ML-KEM subkey: {:?}",
        key.info.subkeys
    );

    let ct = p
        .encrypt(b"pqc hello", &[&key.public], &EncryptOptions::default())
        .unwrap();
    let pt = p.decrypt(&ct, &key.secret, None).unwrap();
    assert_eq!(pt.plaintext, b"pqc hello");

    let sig = p
        .sign(
            b"pqc signed",
            &key.secret,
            None,
            &SignOptions {
                armored: false,
                detached: true,
            },
        )
        .unwrap();
    let v = p.verify(b"pqc signed", &sig.bytes, &key.public).unwrap();
    assert_eq!(v.validity, SignatureValidity::CryptographicallyValid);
}

fn primary_key_version(bytes: &[u8]) -> u8 {
    assert_eq!(bytes[0] & 0xC0, 0xC0, "expected a new-format packet");
    let mut i = 1usize;
    let len = bytes[i];
    i += 1;
    if len < 192 {
    } else if len < 224 {
        i += 1;
    } else if len == 255 {
        i += 4;
    } else {
        panic!("partial body length");
    }
    bytes[i]
}

#[test]
fn rfc9580_classical_roundtrip_and_v4_still_decrypts() {
    let p = pgp();
    let v6 = p
        .generate_key(&GenerateKeyOptions {
            userid: "Ada <ada@example.com>".into(),
            passphrase: None,
            profile: KeyProfile::Rfc9580Cv25519,
        })
        .expect("v6 generate");
    assert_eq!(primary_key_version(&v6.public), 6);
    assert!(!v6.info.is_pqc());

    let ct = p
        .encrypt(b"v6 hello", &[&v6.public], &EncryptOptions::default())
        .unwrap();
    let pt = p.decrypt(&ct, &v6.secret, None).unwrap();
    assert_eq!(pt.plaintext, b"v6 hello");

    let v4 = gen("Legacy <legacy@example.com>");
    assert_eq!(primary_key_version(&v4.public), 4);
    let legacy = p
        .encrypt(b"v4 hello", &[&v4.public], &EncryptOptions::default())
        .unwrap();
    assert_eq!(
        p.decrypt(&legacy, &v4.secret, None).unwrap().plaintext,
        b"v4 hello"
    );

    let mixed = p
        .encrypt(
            b"mixed",
            &[&v6.public, &v4.public],
            &EncryptOptions::default(),
        )
        .unwrap();
    assert_eq!(p.decrypt(&mixed, &v6.secret, None).unwrap().plaintext, b"mixed");
    assert_eq!(p.decrypt(&mixed, &v4.secret, None).unwrap().plaintext, b"mixed");
}

#[test]
fn rfc9980_message_is_aes256_seipdv2_and_pop_signature_verifies() {
    use sequoia_openpgp::cert::Preferences;
    use sequoia_openpgp::packet::{Packet, Tag, SEIP};
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::policy::StandardPolicy;
    use sequoia_openpgp::types::{AEADAlgorithm, SymmetricAlgorithm};
    use sequoia_openpgp::{Cert, PacketPile};

    let p = pgp();
    if !p.rfc9980_ready() {
        return;
    }
    let key = p
        .generate_key(&GenerateKeyOptions {
            userid: "Pqc <pqc@example.com>".into(),
            passphrase: None,
            profile: KeyProfile::Rfc9980MlDsa65,
        })
        .unwrap();
    let ct = p
        .encrypt(b"pqc hello", &[&key.public], &EncryptOptions::default())
        .unwrap();
    let pile = PacketPile::from_bytes(&ct).unwrap();
    let mut pkesks = 0;
    let mut saw_seip2 = false;
    for pkt in pile.children() {
        assert_ne!(pkt.tag(), Tag::SED, "obsolete SED packet");
        match pkt {
            Packet::SEIP(SEIP::V2(seip)) => {
                assert_eq!(seip.symmetric_algo(), SymmetricAlgorithm::AES256);
                assert_eq!(seip.aead(), AEADAlgorithm::OCB);
                saw_seip2 = true;
            }
            Packet::PKESK(_) => pkesks += 1,
            _ => {}
        }
    }
    assert_eq!(pkesks, 1);
    assert!(saw_seip2);

    let cert = Cert::from_bytes(&key.public).unwrap();
    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).unwrap();
    let sym = vc.preferred_symmetric_algorithms().unwrap();
    assert!(sym.contains(&SymmetricAlgorithm::AES256));
    let aead = vc.preferred_aead_ciphersuites().unwrap();
    assert!(aead.iter().any(|(sym, aead)| {
        *sym == SymmetricAlgorithm::AES256 && *aead == AEADAlgorithm::OCB
    }));

    let pop = p
        .sign_pop(b"artifact-pop", &key.secret, None, "scomm-pop@scomm.ai")
        .unwrap();
    assert_pop_signature(&pop, &key.public, b"artifact-pop");
    let rejected = p.verify(b"artifact-pop", &pop, &key.public).unwrap();
    assert_eq!(
        rejected.validity,
        SignatureValidity::CryptographicallyInvalid,
        "mail verification must reject the critical PoP notation"
    );
}

fn assert_pop_signature(sig_bytes: &[u8], _public: &[u8], _data: &[u8]) {
    use sequoia_openpgp::packet::Packet;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::PacketPile;

    let pile = PacketPile::from_bytes(sig_bytes).unwrap();
    let signature = match pile.children().next() {
        Some(Packet::Signature(sig)) => sig,
        other => panic!("expected a signature packet, got {other:?}"),
    };
    assert_eq!(signature.version(), 6);
    assert!(
        sig_bytes
            .windows(b"scomm-pop@scomm.ai".len())
            .any(|w| w == b"scomm-pop@scomm.ai"),
        "missing PoP notation"
    );
}
