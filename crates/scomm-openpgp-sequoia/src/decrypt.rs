use std::io::{self, Read};

use scomm_openpgp_core::*;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::Cert;

use crate::{
    decrypt_policy, fingerprint_of, generate_policy, key_id_of, parse_cert, reject_librepgp,
};

/// Compression lets a small message expand without bound, so decrypted output
/// above this is refused instead of exhausting memory.
const MAX_PLAINTEXT_BYTES: u64 = 256 * 1024 * 1024;

fn read_limited(reader: impl io::Read, limit: u64) -> Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut plaintext)
        .map_err(|_| OpenPgpError::DecryptionFailed)?;
    if plaintext.len() as u64 > limit {
        return Err(OpenPgpError::MalformedMessage);
    }
    Ok(plaintext)
}

pub struct DecryptOutcome {
    pub plaintext: Vec<u8>,
    pub recipient_key_id: Option<OpenPgpKeyId>,
    pub signatures: Vec<SignatureInfo>,
}

struct Helper {
    secret: Cert,
    password: Option<Password>,
    signers: Vec<Cert>,
    recipient_key_id: Option<OpenPgpKeyId>,
    signatures: Vec<SignatureInfo>,
}

impl Helper {
    fn new(secret: Cert, passphrase: Option<&str>, signers: Vec<Cert>) -> Self {
        Self {
            secret,
            password: passphrase.filter(|s| !s.is_empty()).map(Password::from),
            signers,
            recipient_key_id: None,
            signatures: Vec::new(),
        }
    }
}

/// N1: a signature that verified under the permissive decrypt policy is
/// weak unless it also holds under the current policy: its hash for
/// collision resistance, and the signer key and its binding at the time it
/// signed.
fn is_weak(good: &sequoia_openpgp::parse::stream::GoodChecksum<'_>) -> bool {
    use sequoia_openpgp::policy::{HashAlgoSecurity, Policy};
    let strict = generate_policy();
    if strict
        .signature(good.sig, HashAlgoSecurity::CollisionResistance)
        .is_err()
    {
        return true;
    }
    let when = good.sig.signature_creation_time();
    let fp = good.ka.key().fingerprint();
    let Ok(valid) = good.ka.cert().with_policy(&strict, when) else {
        return true;
    };
    !valid
        .keys()
        .key_handle(fp)
        .for_signing()
        .any(|ka| strict.key(&ka).is_ok())
}

impl VerificationHelper for Helper {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(self.signers.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    match r {
                        Ok(good) => {
                            self.signatures.push(SignatureInfo {
                                fingerprint: Some(fingerprint_of(good.ka.key().fingerprint())),
                                key_id: Some(key_id_of(&good.ka.key().keyid())),
                                validity: SignatureValidity::CryptographicallyValid,
                                created_at: None,
                                weak_algorithm: is_weak(&good),
                            });
                        }
                        Err(_) => {
                            self.signatures.push(SignatureInfo {
                                fingerprint: None,
                                key_id: None,
                                validity: SignatureValidity::CryptographicallyInvalid,
                                created_at: None,
                                weak_algorithm: false,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl DecryptionHelper for Helper {
    fn decrypt(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(
            Option<SymmetricAlgorithm>,
            &sequoia_openpgp::crypto::SessionKey,
        ) -> bool,
    ) -> sequoia_openpgp::Result<Option<Cert>> {
        let p = decrypt_policy();
        for ka in self
            .secret
            .keys()
            .secret()
            .with_policy(&p, None)
            .for_storage_encryption()
            .for_transport_encryption()
        {
            let key = ka.key().clone();
            let unlocked = if let Some(ref pw) = self.password {
                match key.decrypt_secret(pw) {
                    Ok(k) => k,
                    Err(_) => continue,
                }
            } else {
                key
            };
            let Ok(mut pair) = unlocked.into_keypair() else {
                continue;
            };
            for pkesk in pkesks {
                if pkesk
                    .decrypt(&mut pair, sym_algo)
                    .map(|(algo, sk)| decrypt(algo, &sk))
                    .unwrap_or(false)
                {
                    self.recipient_key_id = Some(key_id_of(&ka.key().keyid()));
                    return Ok(Some(self.secret.clone()));
                }
            }
        }
        Err(anyhow::anyhow!("decryption failed"))
    }
}

pub fn decrypt(
    ciphertext: &[u8],
    private_key: &[u8],
    passphrase: Option<&str>,
    signer_public_keys: &[&[u8]],
) -> Result<DecryptOutcome> {
    let secret = parse_cert(private_key)?;
    reject_librepgp(&secret)?;
    let mut signers = Vec::new();
    for b in signer_public_keys {
        let c = parse_cert(b)?;
        reject_librepgp(&c)?;
        signers.push(c);
    }
    let helper = Helper::new(secret, passphrase, signers);
    let p = decrypt_policy();
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|_| OpenPgpError::MalformedMessage)?
        .with_policy(&p, None, helper)
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("decrypt") {
                OpenPgpError::DecryptionFailed
            } else {
                OpenPgpError::MalformedMessage
            }
        })?;
    let plaintext = read_limited(&mut decryptor, MAX_PLAINTEXT_BYTES)?;
    let helper = decryptor.into_helper();
    if helper.recipient_key_id.is_none() && plaintext.is_empty() {
        return Err(OpenPgpError::DecryptionFailed);
    }
    Ok(DecryptOutcome {
        plaintext,
        recipient_key_id: helper.recipient_key_id,
        signatures: helper.signatures,
    })
}

struct VerifyHelper {
    cert: Cert,
    validity: SignatureValidity,
    fingerprint: Option<OpenPgpFingerprint>,
    key_id: Option<OpenPgpKeyId>,
    primary: Option<OpenPgpFingerprint>,
    weak: bool,
}

impl VerificationHelper for VerifyHelper {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                if results.is_empty() {
                    self.validity = SignatureValidity::MalformedSignature;
                    continue;
                }
                for r in results {
                    match r {
                        Ok(good) => {
                            self.validity = SignatureValidity::CryptographicallyValid;
                            self.fingerprint = Some(fingerprint_of(good.ka.key().fingerprint()));
                            self.key_id = Some(key_id_of(&good.ka.key().keyid()));
                            self.primary = Some(fingerprint_of(good.ka.cert().fingerprint()));
                            self.weak = is_weak(&good);
                        }
                        Err(_) => {
                            if self.validity != SignatureValidity::CryptographicallyValid {
                                self.validity = SignatureValidity::CryptographicallyInvalid;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn verify_detached(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<VerificationResult> {
    let cert = parse_cert(public_key)?;
    reject_librepgp(&cert)?;
    let helper = VerifyHelper {
        cert,
        validity: SignatureValidity::UnknownSigner,
        fingerprint: None,
        key_id: None,
        primary: None,
        weak: false,
    };
    // Detached PGP/MIME signatures are checked under the current policy
    // (N1), so a SHA-1 signature does not verify here.
    let p = generate_policy();
    let mut verifier = DetachedVerifierBuilder::from_bytes(signature)
        .map_err(|_| OpenPgpError::MalformedMessage)?
        .with_policy(&p, None, helper)
        .map_err(|_| OpenPgpError::MalformedMessage)?;
    verifier
        .verify_bytes(data)
        .map_err(|_| OpenPgpError::BadSignature)?;
    let helper = verifier.into_helper();
    Ok(VerificationResult {
        validity: helper.validity,
        signer_fingerprint: helper.fingerprint,
        signer_key_id: helper.key_id,
        signer_primary_fingerprint: helper.primary,
        weak_algorithm: helper.weak,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_limited_accepts_the_limit_and_refuses_more() {
        assert_eq!(read_limited(&b"abcd"[..], 4).unwrap(), b"abcd");
        assert!(matches!(
            read_limited(&b"abcde"[..], 4),
            Err(OpenPgpError::MalformedMessage)
        ));
    }
}
