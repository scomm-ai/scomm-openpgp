//! Raw artifact PoP: dual-sign ID 30 and dual-KEM ID 35 without OpenPGP packets.
//!
//! Signing goes through Sequoia's public signer, so the OpenSSL backend
//! produces both halves. The hybrid shared secret calls OpenSSL directly:
//! Sequoia's public decrypt only returns a session key.

use ossl::asymcipher::{EncOp, OsslAsymcipher};
use ossl::OsslSecret;
use ossl::derive::EcdhDerive;
use ossl::pkey::{EccData, EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use sequoia_openpgp::crypto::mpi::{self, SecretKeyMaterial as MpiSecret};
use sequoia_openpgp::crypto::{Password, Signer};
use sequoia_openpgp::packet::key::SecretKeyMaterial;
use sequoia_openpgp::types::HashAlgorithm;
use sequoia_openpgp::Cert;
use scomm_openpgp_core::*;

use crate::{parse_cert, reject_librepgp};

const MLKEM_CT_LEN: usize = 1088;

fn unlock_cert(private_key: &[u8], _passphrase: Option<&str>) -> Result<Cert> {
    let cert = parse_cert(private_key)?;
    reject_librepgp(&cert)?;
    if !cert.is_tsk() {
        return Err(OpenPgpError::InvalidKey("no secret key material".into()));
    }
    Ok(cert)
}

fn password(passphrase: Option<&str>) -> Option<Password> {
    passphrase.filter(|s| !s.is_empty()).map(Password::from)
}

fn unlock_key(
    key: sequoia_openpgp::packet::Key<
        sequoia_openpgp::packet::key::SecretParts,
        sequoia_openpgp::packet::key::UnspecifiedRole,
    >,
    password: &Option<Password>,
) -> Result<
    sequoia_openpgp::packet::Key<
        sequoia_openpgp::packet::key::SecretParts,
        sequoia_openpgp::packet::key::UnspecifiedRole,
    >,
> {
    if key.has_unencrypted_secret() {
        return Ok(key);
    }
    let Some(pw) = password else {
        return Err(OpenPgpError::InvalidArgument("passphrase required".into()));
    };
    key.decrypt_secret(pw)
        .map_err(|_| OpenPgpError::DecryptionFailed)
}

pub fn pop_sign_composite(
    data: &[u8],
    private_key: &[u8],
    passphrase: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = unlock_cert(private_key, passphrase)?;
    let pw = password(passphrase);
    for ka in cert.keys().secret() {
        if u8::from(ka.key().pk_algo()) != 30 {
            continue;
        }
        let unlocked = unlock_key(ka.key().clone(), &pw)?;
        let mut pair = unlocked
            .into_keypair()
            .map_err(|_| OpenPgpError::InvalidKey("unlock ML-DSA-65+Ed25519".into()))?;
        // Sequoia passes this buffer straight to Ed25519 and ML-DSA-65 for
        // algorithm 30. It is the message, not a digest.
        let signature = Signer::sign(&mut pair, HashAlgorithm::SHA256, data)
            .map_err(|_| OpenPgpError::UnsupportedAlgorithm("composite sign".into()))?;
        return match signature {
            mpi::Signature::MLDSA65_Ed25519 { mldsa, eddsa } => {
                Ok((mldsa.to_vec(), eddsa.as_ref().to_vec()))
            }
            _ => Err(OpenPgpError::UnsupportedAlgorithm(
                "primary secret is not ML-DSA-65+Ed25519".into(),
            )),
        };
    }
    Err(OpenPgpError::NoSuitableSigningKey)
}

fn x25519_raw(ephemeral: &[u8]) -> Result<[u8; 32]> {
    if ephemeral.len() == 32 {
        return ephemeral
            .try_into()
            .map_err(|_| OpenPgpError::InvalidArgument("x25519".into()));
    }
    if ephemeral.len() == 44 {
        return ephemeral[12..]
            .try_into()
            .map_err(|_| OpenPgpError::InvalidArgument("x25519 spki".into()));
    }
    Err(OpenPgpError::InvalidArgument(
        "ephemeral X25519 must be 32 raw octets or SPKI".into(),
    ))
}

pub fn pop_hybrid_shared(
    private_key: &[u8],
    passphrase: Option<&str>,
    kem_ciphertext: &[u8],
    ephemeral_x25519: &[u8],
) -> Result<Vec<u8>> {
    if kem_ciphertext.len() != MLKEM_CT_LEN {
        return Err(OpenPgpError::InvalidArgument(
            "ML-KEM-768 ciphertext must be 1088 octets".into(),
        ));
    }
    let eph = x25519_raw(ephemeral_x25519)?;
    let cert = unlock_cert(private_key, passphrase)?;
    let pw = password(passphrase);
    for ka in cert.keys().secret() {
        if u8::from(ka.key().pk_algo()) != 35 {
            continue;
        }
        let unlocked = unlock_key(ka.key().clone(), &pw)?;
        return match unlocked.secret() {
            SecretKeyMaterial::Unencrypted(unenc) => unenc.map(|mpis| match mpis {
                MpiSecret::MLKEM768_X25519 { ecdh, mlkem } => {
                    let x_seed: [u8; 32] = ecdh[..]
                        .try_into()
                        .map_err(|_| OpenPgpError::InvalidKey("X25519 seed".into()))?;
                    if mlkem.len() != 64 {
                        return Err(OpenPgpError::InvalidKey("ML-KEM-768 seed".into()));
                    }
                    let ml_shared = mlkem_decaps(&mlkem[..], kem_ciphertext)?;
                    let x_shared = x25519_dh(&x_seed, &eph)?;
                    let mut concat = Vec::with_capacity(64);
                    concat.extend_from_slice(&ml_shared);
                    concat.extend_from_slice(&x_shared);
                    Ok(concat)
                }
                _ => Err(OpenPgpError::UnsupportedAlgorithm(
                    "encryption secret is not ML-KEM-768+X25519".into(),
                )),
            }),
            SecretKeyMaterial::Encrypted(_) => Err(OpenPgpError::DecryptionFailed),
        };
    }
    Err(OpenPgpError::NoSuitableEncryptionKey)
}

fn ossl_ctx() -> ossl::OsslContext {
    ossl::OsslContext::new_lib_ctx()
}

fn mlkem_decaps(seed: &[u8], ciphertext: &[u8]) -> Result<[u8; 32]> {
    let ctx = ossl_ctx();
    let mut key = EvpPkey::import(
        &ctx,
        EvpPkeyType::MlKem768,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|_| OpenPgpError::InvalidKey("ML-KEM-768 seed".into()))?;
    let mut decap = OsslAsymcipher::new(&ctx, EncOp::Decapsulate, &mut key, None)
        .map_err(|_| OpenPgpError::DecryptionFailed)?;
    let shared = decap
        .decapsulate(ciphertext)
        .map_err(|_| OpenPgpError::DecryptionFailed)?;
    let bytes: &[u8] = shared.as_ref();
    bytes
        .try_into()
        .map_err(|_| OpenPgpError::DecryptionFailed)
}

fn x25519_dh(seed: &[u8; 32], ephemeral: &[u8; 32]) -> Result<[u8; 32]> {
    let ctx = ossl_ctx();
    let mut secret = EvpPkey::import(
        &ctx,
        EvpPkeyType::X25519,
        PkeyData::Ecc(EccData {
            pubkey: None,
            prikey: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|_| OpenPgpError::InvalidKey("X25519 seed".into()))?;
    let mut public = EvpPkey::import(
        &ctx,
        EvpPkeyType::X25519,
        PkeyData::Ecc(EccData {
            pubkey: Some(ephemeral.to_vec()),
            prikey: None,
        }),
    )
    .map_err(|_| OpenPgpError::InvalidArgument("X25519 ephemeral".into()))?;
    let mut deriver = EcdhDerive::new(&ctx, &mut secret).map_err(|_| OpenPgpError::DecryptionFailed)?;
    let mut shared = vec![0u8; 32];
    deriver
        .derive(&mut public, &mut shared)
        .map_err(|_| OpenPgpError::DecryptionFailed)?;
    shared
        .try_into()
        .map_err(|_| OpenPgpError::DecryptionFailed)
}
