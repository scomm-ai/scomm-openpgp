//! Curve25519 secret export for classical artifact proof of possession.

use sequoia_openpgp::crypto::mpi::SecretKeyMaterial as MpiSecret;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::packet::key::SecretKeyMaterial;
use sequoia_openpgp::Cert;
use scomm_openpgp_core::*;

use crate::{parse_cert, reject_librepgp};

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

pub fn export_curve_secret(
    private_key: &[u8],
    passphrase: Option<&str>,
    signing: bool,
) -> Result<Vec<u8>> {
    let cert = unlock_cert(private_key, passphrase)?;
    let pw = password(passphrase);
    for ka in cert.keys().secret() {
        let unlocked = unlock_key(ka.key().clone(), &pw)?;
        match unlocked.secret() {
            SecretKeyMaterial::Unencrypted(unenc) => {
                if let Some(bytes) = unenc.map(|mpis| curve_scalar(&mpis, signing)) {
                    if bytes.len() != 32 {
                        return Err(OpenPgpError::InvalidKey("curve25519 secret".into()));
                    }
                    return Ok(bytes);
                }
            }
            SecretKeyMaterial::Encrypted(_) => return Err(OpenPgpError::DecryptionFailed),
        }
    }
    Err(if signing {
        OpenPgpError::NoSuitableSigningKey
    } else {
        OpenPgpError::NoSuitableEncryptionKey
    })
}

fn curve_scalar(mpis: &MpiSecret, signing: bool) -> Option<Vec<u8>> {
    let bytes: &[u8] = match (mpis, signing) {
        (MpiSecret::Ed25519 { x }, true) => x.as_ref(),
        (MpiSecret::X25519 { x }, false) => x.as_ref(),
        _ => return None,
    };
    Some(bytes.to_vec())
}

