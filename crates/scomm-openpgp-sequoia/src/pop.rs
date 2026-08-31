//! Raw artifact PoP: dual-sign ID 30 and dual-KEM ID 35 without OpenPGP packets.

use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey};
use ml_kem::kem::Decapsulate;
use ml_kem::{DecapsulationKey, MlKem768};
use sequoia_openpgp::crypto::mpi::SecretKeyMaterial as MpiSecret;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::packet::key::SecretKeyMaterial;
use sequoia_openpgp::Cert;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use scomm_openpgp_core::*;

use crate::{parse_cert, reject_librepgp};

const SPKI_X25519_LEN: usize = 44;
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
        return match unlocked.secret() {
            SecretKeyMaterial::Unencrypted(unenc) => unenc.map(|mpis| match mpis {
                MpiSecret::MLDSA65_Ed25519 { eddsa, mldsa } => {
                    let ed_seed: [u8; 32] = eddsa[..]
                        .try_into()
                        .map_err(|_| OpenPgpError::InvalidKey("Ed25519 seed".into()))?;
                    let ml_seed: [u8; 32] = mldsa[..]
                        .try_into()
                        .map_err(|_| OpenPgpError::InvalidKey("ML-DSA seed".into()))?;
                    let ed_sig = SigningKey::from_bytes(&ed_seed).sign(data).to_bytes();
                    let ml_key = MlDsaSigningKey::<MlDsa65>::from_seed((&ml_seed).into());
                    use ml_dsa::signature::Signer;
                    let ml_sig = Signer::sign(&ml_key, data).encode();
                    Ok((ml_sig.to_vec(), ed_sig.to_vec()))
                }
                _ => Err(OpenPgpError::UnsupportedAlgorithm(
                    "primary secret is not ML-DSA-65+Ed25519".into(),
                )),
            }),
            SecretKeyMaterial::Encrypted(_) => Err(OpenPgpError::DecryptionFailed),
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
    if ephemeral.len() == SPKI_X25519_LEN {
        return ephemeral[SPKI_X25519_LEN - 32..]
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
    let ct: [u8; MLKEM_CT_LEN] = kem_ciphertext
        .try_into()
        .map_err(|_| OpenPgpError::InvalidArgument("kem ct".into()))?;
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
                    let kem_seed = mlkem[..].to_vec();
                    if kem_seed.len() != 64 {
                        return Err(OpenPgpError::InvalidKey("ML-KEM-768 seed".into()));
                    }
                    let x_secret = StaticSecret::from(x_seed);
                    let x_shared = x_secret.diffie_hellman(&X25519Public::from(eph));
                    let decaps = DecapsulationKey::<MlKem768>::from_seed(
                        (&kem_seed[..]).try_into().expect("64"),
                    );
                    let ml_shared = decaps.decapsulate((&ct).into());
                    let ml_bytes: [u8; 32] = ml_shared.into();
                    let mut concat = Vec::with_capacity(64);
                    concat.extend_from_slice(&ml_bytes);
                    concat.extend_from_slice(x_shared.as_bytes());
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
