use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;
use sequoia_openpgp::{parse::Parse, Cert};

#[test]
fn nist_curves_roundtrip() {
    let pgp = SequoiaOpenPgp::new();
    for (profile, curve, version) in [
        (KeyProfile::ClassicalP256, "p256", 4),
        (KeyProfile::ClassicalP384, "p384", 4),
        (KeyProfile::ClassicalP521, "p521", 4),
        (KeyProfile::Rfc9580P256, "p256", 6),
        (KeyProfile::Rfc9580P384, "p384", 6),
        (KeyProfile::Rfc9580P521, "p521", 6),
    ] {
        let key = pgp
            .generate_key(&GenerateKeyOptions {
                userid: "Curve Test <curve@example.com>".into(),
                profile,
                passphrase: Some("curve-test".into()),
                validity_years: Some(2),
            })
            .unwrap();
        let cert = Cert::from_bytes(&key.public).unwrap();
        assert_eq!(cert.primary_key().key().version(), version);
        assert_eq!(key.info.algorithm, format!("openpgp-ecdsa-{curve}"));
        assert!(key
            .info
            .subkeys
            .iter()
            .any(|k| k.algorithm == format!("openpgp-ecdh-{curve}")));
        let armor = pgp.armor(ArmorKind::SecretKey, &key.secret).unwrap();
        let secret = pgp.dearmor(&armor).unwrap();
        let public = pgp.export_public_key(&secret).unwrap();
        assert_eq!(
            pgp.inspect_key(&public).unwrap().fingerprint,
            key.info.fingerprint
        );
        let data = b"NIST curve roundtrip";
        let sig = pgp
            .sign(data, &secret, Some("curve-test"), &SignOptions::default())
            .unwrap();
        assert_eq!(
            pgp.verify(data, &sig.bytes, &public).unwrap().validity,
            SignatureValidity::CryptographicallyValid
        );
        assert_ne!(
            pgp.verify(b"altered", &sig.bytes, &public)
                .unwrap()
                .validity,
            SignatureValidity::CryptographicallyValid
        );
        let encrypted = pgp
            .encrypt(data, &[&public], &EncryptOptions::default())
            .unwrap();
        assert_eq!(
            pgp.decrypt(&encrypted, &secret, Some("curve-test"))
                .unwrap()
                .plaintext,
            data
        );
        assert!(pgp.decrypt(&encrypted, &secret, Some("wrong")).is_err());
    }
}
