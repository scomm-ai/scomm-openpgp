//! N1 (task 4.3): decryption stays permissive for old ciphers, but nothing
//! without integrity protection opens, and signatures that pass only the
//! old policy are flagged weak.

use std::io::Write;

use openssl::symm::{Cipher, Crypter, Mode};
use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::packet::pkesk::PKESK3;
use sequoia_openpgp::packet::{Literal, PKESK};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Signer};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{DataFormat, HashAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp::{Packet, Profile};

const BODY: &[u8] = b"n1 policy body";

fn pgp() -> SequoiaOpenPgp {
    SequoiaOpenPgp::new()
}

/// A v4 key that advertises only SEIPD v1, so messages to it carry an MDC
/// and may use 64-bit block ciphers.
fn v4_key(userid: &str) -> Cert {
    CertBuilder::general_purpose(Some(userid))
        .set_profile(Profile::RFC4880)
        .unwrap()
        .set_features(sequoia_openpgp::types::Features::empty().set_seipdv1())
        .unwrap()
        .generate()
        .unwrap()
        .0
}

fn secret(cert: &Cert) -> Vec<u8> {
    cert.as_tsk().to_vec().unwrap()
}

fn public(cert: &Cert) -> Vec<u8> {
    cert.to_vec().unwrap()
}

/// Encrypts to `to` with `cipher`, signed by `signer` with `hash` when given.
fn message(
    to: &Cert,
    cipher: SymmetricAlgorithm,
    signer: Option<(&Cert, HashAlgorithm)>,
) -> Vec<u8> {
    let p = StandardPolicy::new();
    let recipients = to
        .keys()
        .with_policy(&p, None)
        .supported()
        .for_transport_encryption();
    let mut sink = Vec::new();
    let m = Message::new(&mut sink);
    let m = Encryptor::for_recipients(m, recipients)
        .symmetric_algo(cipher)
        .build()
        .unwrap();
    let m = match signer {
        Some((cert, hash)) => {
            let key = cert
                .keys()
                .secret()
                .with_policy(&p, None)
                .for_signing()
                .next()
                .unwrap()
                .key()
                .clone()
                .into_keypair()
                .unwrap();
            Signer::new(m, key)
                .unwrap()
                .hash_algo(hash)
                .unwrap()
                .build()
                .unwrap()
        }
        None => m,
    };
    let mut lit = LiteralWriter::new(m).build().unwrap();
    lit.write_all(BODY).unwrap();
    lit.finalize().unwrap();
    sink
}

fn open(ct: &[u8], key: &Cert, signers: &[&Cert]) -> Result<DecryptVerifyResult> {
    let signer_keys: Vec<Vec<u8>> = signers.iter().map(|c| public(c)).collect();
    let refs: Vec<&[u8]> = signer_keys.iter().map(Vec::as_slice).collect();
    pgp().decrypt_and_verify(ct, &secret(key), None, &refs)
}

/// OpenPGP CFB with resync over AES-256 (RFC 4880 section 13.9): the
/// Symmetrically Encrypted Data packet older software wrote, which has no
/// integrity check.
fn sed_packet(session_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let block = |input: &[u8]| -> [u8; 16] {
        let mut c = Crypter::new(Cipher::aes_256_ecb(), Mode::Encrypt, session_key, None).unwrap();
        c.pad(false);
        let mut out = [0u8; 32];
        let n = c.update(input, &mut out).unwrap();
        assert_eq!(n, 16);
        out[..16].try_into().unwrap()
    };
    let cfb = |iv: [u8; 16], data: &[u8]| -> Vec<u8> {
        let mut fr = iv;
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(16) {
            let ks = block(&fr);
            let c: Vec<u8> = chunk.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect();
            if c.len() == 16 {
                fr.copy_from_slice(&c);
            }
            out.extend_from_slice(&c);
        }
        out
    };
    let mut prefix = [0u8; 18];
    openssl::rand::rand_bytes(&mut prefix[..16]).unwrap();
    prefix[16] = prefix[14];
    prefix[17] = prefix[15];
    // First 18 bytes from IV 0 (the 17th and 18th from the first block's
    // ciphertext), then resync on ciphertext bytes 2..18.
    let first = cfb([0u8; 16], &prefix[..16]);
    let ks = block(&first[..16]);
    let mut body = first.clone();
    body.push(prefix[16] ^ ks[0]);
    body.push(prefix[17] ^ ks[1]);
    let resync: [u8; 16] = body[2..18].try_into().unwrap();
    body.extend(cfb(resync, plaintext));
    let mut packet = vec![0xC9];
    let n = body.len();
    if n < 192 {
        packet.push(n as u8);
    } else {
        assert!(n < 8384, "two-octet length");
        packet.push((((n - 192) >> 8) + 192) as u8);
        packet.push(((n - 192) & 0xff) as u8);
    }
    packet.extend(body);
    packet
}

fn sed_message(to: &Cert) -> Vec<u8> {
    let p = StandardPolicy::new();
    let key = to
        .keys()
        .with_policy(&p, None)
        .for_transport_encryption()
        .next()
        .unwrap()
        .key()
        .clone();
    let session = SessionKey::new(32).unwrap();
    let pkesk = PKESK3::for_recipient(SymmetricAlgorithm::AES256, &session, &key).unwrap();
    let mut literal = Literal::new(DataFormat::Binary);
    literal.set_body(BODY.to_vec());
    let literal = Packet::from(literal).to_vec().unwrap();
    let mut out = Packet::from(PKESK::from(pkesk)).to_vec().unwrap();
    out.extend(sed_packet(&session, &literal));
    out
}

/// The message is valid SED: GnuPG 2.4 opens it with `--ignore-mdc-error`
/// and warns "message was not integrity protected".
#[test]
fn sed_without_integrity_protection_is_refused() {
    let bob = v4_key("bob@example.com");
    let ct = sed_message(&bob);
    let got = open(&ct, &bob, &[]);
    assert!(got.is_err(), "SED opened: {:?}", got.map(|r| r.plaintext));
}

#[test]
fn a_broken_mdc_releases_no_plaintext() {
    let bob = v4_key("bob@example.com");
    let ct = message(&bob, SymmetricAlgorithm::AES256, None);
    assert_eq!(open(&ct, &bob, &[]).unwrap().plaintext, BODY);
    let seipd_v1 = sequoia_openpgp::PacketPile::from_bytes(&ct)
        .unwrap()
        .children()
        .any(|p| matches!(p, Packet::SEIP(sequoia_openpgp::packet::SEIP::V1(_))));
    assert!(seipd_v1, "the message must be SEIPD v1 for this test");
    // The MDC is the last 22 bytes of SEIPD v1; break its SHA-1.
    let mut broken = ct.clone();
    let last = broken.len() - 1;
    broken[last] ^= 0x01;
    assert!(open(&broken, &bob, &[]).is_err());
}

#[test]
#[allow(deprecated)] // old ciphers on purpose: inbox mail still uses them
fn legacy_ciphers_still_decrypt() {
    let bob = v4_key("bob@example.com");
    for cipher in [SymmetricAlgorithm::TripleDES, SymmetricAlgorithm::CAST5] {
        if !cipher.is_supported() {
            println!("skipped: {cipher:?} not in this backend");
            continue;
        }
        let ct = message(&bob, cipher, None);
        assert_eq!(open(&ct, &bob, &[]).unwrap().plaintext, BODY, "{cipher:?}");
    }
}

#[test]
fn modern_and_sha1_signatures_report_weakness() {
    let (alice, bob) = (v4_key("alice@example.com"), v4_key("bob@example.com"));
    for (hash, weak) in [
        (HashAlgorithm::SHA512, false),
        (HashAlgorithm::SHA256, false),
        (HashAlgorithm::SHA1, true),
    ] {
        let ct = message(&bob, SymmetricAlgorithm::AES256, Some((&alice, hash)));
        let out = open(&ct, &bob, &[&alice]).unwrap();
        assert_eq!(out.plaintext, BODY);
        assert_eq!(out.signatures.len(), 1, "{hash:?}");
        let s = &out.signatures[0];
        assert_eq!(
            s.validity,
            SignatureValidity::CryptographicallyValid,
            "{hash:?}"
        );
        assert_eq!(s.weak_algorithm, weak, "{hash:?}");
    }
}

/// Detached PGP/MIME signatures run under the current policy: modern ones
/// verify and name the primary key; SHA-1 ones do not verify.
#[test]
fn detached_signatures_use_the_current_policy() {
    use sequoia_openpgp::serialize::stream::Signer;
    let alice = v4_key("alice@example.com");
    let p = StandardPolicy::new();
    let signing = alice
        .keys()
        .secret()
        .with_policy(&p, None)
        .for_signing()
        .next()
        .unwrap();
    let subkey_fp = signing.key().fingerprint();
    for (hash, verifies) in [(HashAlgorithm::SHA256, true), (HashAlgorithm::SHA1, false)] {
        let pair = signing.key().clone().into_keypair().unwrap();
        let mut sig = Vec::new();
        let m = Message::new(&mut sig);
        let mut s = Signer::new(m, pair)
            .unwrap()
            .detached()
            .hash_algo(hash)
            .unwrap()
            .build()
            .unwrap();
        s.write_all(BODY).unwrap();
        s.finalize().unwrap();
        let v = pgp().verify(BODY, &sig, &public(&alice)).unwrap();
        if verifies {
            assert_eq!(
                v.validity,
                SignatureValidity::CryptographicallyValid,
                "{hash:?}"
            );
            assert!(!v.weak_algorithm);
            assert_eq!(v.signer_fingerprint.unwrap().0, subkey_fp.as_bytes());
            assert_eq!(
                v.signer_primary_fingerprint.unwrap().0,
                alice.fingerprint().as_bytes(),
                "pins use the primary key"
            );
        } else {
            assert_ne!(
                v.validity,
                SignatureValidity::CryptographicallyValid,
                "{hash:?}"
            );
        }
    }
}
