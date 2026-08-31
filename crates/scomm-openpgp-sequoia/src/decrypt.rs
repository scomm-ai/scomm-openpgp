use std::io;

use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::Cert;
use scomm_openpgp_core::*;

use crate::{
    decrypt_policy, fingerprint_of, generate_policy, key_id_of, parse_cert, reject_librepgp,
};

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
                            });
                        }
                        Err(_) => {
                            self.signatures.push(SignatureInfo {
                                fingerprint: None,
                                key_id: None,
                                validity: SignatureValidity::CryptographicallyInvalid,
                                created_at: None,
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
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &sequoia_openpgp::crypto::SessionKey) -> bool,
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
    let mut plaintext = Vec::new();
    io::copy(&mut decryptor, &mut plaintext).map_err(|_| OpenPgpError::DecryptionFailed)?;
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
    };
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
    })
}
