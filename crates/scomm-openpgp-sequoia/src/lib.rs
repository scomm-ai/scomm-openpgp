//! Sequoia backend. Sequoia types stay inside this crate.

use std::io::{self, Write};

use sequoia_openpgp::armor::{self, Kind as SequoiaArmorKind};
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::cert::CipherSuite;
use sequoia_openpgp::types::PublicKeyAlgorithm;
use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::Profile;
use scomm_openpgp_core::*;

mod decrypt;
mod inspect;
mod policy;
mod pop;

pub use policy::{decrypt_policy, generate_policy};

const ALG_ML_DSA_65_ED25519: u8 = 30;
const ALG_ML_KEM_768_X25519: u8 = 35;
const ALG_LIBREPGP_KYBER_768: u8 = 105;
const ALG_LIBREPGP_KYBER_1024: u8 = 106;

pub struct SequoiaOpenPgp;

impl SequoiaOpenPgp {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SequoiaOpenPgp {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenPgpProvider for SequoiaOpenPgp {
    fn rfc9980_ready(&self) -> bool {
        CipherSuite::MLDSA65_Ed25519.is_supported().is_ok()
    }

    fn inspect_key(&self, key: &[u8]) -> Result<OpenPgpKeyInfo> {
        let cert = parse_cert(key)?;
        reject_librepgp(&cert)?;
        inspect::key_info(&cert, &decrypt_policy())
    }

    fn generate_key(&self, options: &GenerateKeyOptions) -> Result<GeneratedKey> {
        if options.userid.trim().is_empty() {
            return Err(OpenPgpError::InvalidArgument(
                "userid is required (e.g. Name <user@example.com>)".into(),
            ));
        }
        let mut builder = CertBuilder::general_purpose(Some(options.userid.as_str()));
        builder = match options.profile {
            KeyProfile::ClassicalCv25519 => builder.set_cipher_suite(CipherSuite::Cv25519),
            KeyProfile::Rfc9980MlDsa65 => builder
                .set_profile(Profile::RFC9580)
                .map_err(|e| OpenPgpError::UnsupportedAlgorithm(e.to_string()))?
                .set_cipher_suite(CipherSuite::MLDSA65_Ed25519),
        };
        if let Some(ref pw) = options.passphrase {
            if !pw.is_empty() {
                builder = builder.set_password(Some(Password::from(pw.as_str())));
            }
        }
        let (cert, _revocation) = builder
            .generate()
            .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
        reject_librepgp(&cert)?;

        let secret = cert
            .as_tsk()
            .to_vec()
            .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
        let public = cert
            .clone()
            .strip_secret_key_material()
            .to_vec()
            .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
        let info = inspect::key_info(&cert, &generate_policy())?;
        Ok(GeneratedKey {
            public,
            secret,
            info,
        })
    }

    fn export_public_key(&self, secret_or_public: &[u8]) -> Result<Vec<u8>> {
        let cert = parse_cert(secret_or_public)?;
        reject_librepgp(&cert)?;
        cert.strip_secret_key_material()
            .to_vec()
            .map_err(|e| OpenPgpError::Internal(e.to_string()))
    }

    fn sign(
        &self,
        data: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
        options: &SignOptions,
    ) -> Result<SignatureResult> {
        let cert = parse_cert(private_key)?;
        reject_librepgp(&cert)?;
        let p = generate_policy();
        let (keypair, fp, kid) = signing_keypair(&cert, passphrase, &p)?;

        let mut sink = Vec::new();
        {
            let message = Message::new(&mut sink);
            let message = maybe_armor(message, options.armored, SequoiaArmorKind::Signature)?;
            let builder =
                Signer::new(message, keypair).map_err(|e| OpenPgpError::Internal(e.to_string()))?;
            if options.detached {
                let mut signer = builder
                    .detached()
                    .build()
                    .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
                signer
                    .write_all(data)
                    .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
                signer
                    .finalize()
                    .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
            } else {
                let signer = builder
                    .build()
                    .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
                let mut literal = LiteralWriter::new(signer)
                    .build()
                    .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
                literal
                    .write_all(data)
                    .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
                literal
                    .finalize()
                    .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
            }
        }
        Ok(SignatureResult {
            bytes: sink,
            fingerprint: fp,
            key_id: kid,
        })
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<VerificationResult> {
        decrypt::verify_detached(data, signature, public_key)
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        recipient_public_keys: &[&[u8]],
        options: &EncryptOptions,
    ) -> Result<Vec<u8>> {
        encrypt_message(plaintext, recipient_public_keys, None, options)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
    ) -> Result<DecryptResult> {
        let out = decrypt::decrypt(ciphertext, private_key, passphrase, &[])?;
        Ok(DecryptResult {
            plaintext: out.plaintext,
            recipient_key_id: out.recipient_key_id,
        })
    }

    fn encrypt_and_sign(
        &self,
        plaintext: &[u8],
        recipient_public_keys: &[&[u8]],
        signing_private_key: &[u8],
        passphrase: Option<&str>,
        options: &EncryptOptions,
    ) -> Result<Vec<u8>> {
        let cert = parse_cert(signing_private_key)?;
        reject_librepgp(&cert)?;
        let p = generate_policy();
        let (keypair, _, _) = signing_keypair(&cert, passphrase, &p)?;
        encrypt_message(plaintext, recipient_public_keys, Some(keypair), options)
    }

    fn decrypt_and_verify(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
        signer_public_keys: &[&[u8]],
    ) -> Result<DecryptVerifyResult> {
        let d = decrypt::decrypt(ciphertext, private_key, passphrase, signer_public_keys)?;
        Ok(DecryptVerifyResult {
            plaintext: d.plaintext,
            recipient_key_id: d.recipient_key_id,
            signatures: d.signatures,
        })
    }

    fn inspect_message(&self, message: &[u8]) -> Result<MessageInfo> {
        inspect::message(message)
    }

    fn armor(&self, kind: ArmorKind, binary: &[u8]) -> Result<Vec<u8>> {
        let kind = match kind {
            ArmorKind::PublicKey => SequoiaArmorKind::PublicKey,
            ArmorKind::SecretKey => SequoiaArmorKind::SecretKey,
            ArmorKind::Signature => SequoiaArmorKind::Signature,
            ArmorKind::Message => SequoiaArmorKind::Message,
        };
        let mut out = Vec::new();
        {
            let mut w = armor::Writer::new(&mut out, kind)
                .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
            w.write_all(binary)
                .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
            w.finalize()
                .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
        }
        Ok(out)
    }

    fn dearmor(&self, armored: &[u8]) -> Result<Vec<u8>> {
        let mut r = armor::Reader::from_reader(armored, armor::ReaderMode::Tolerant(None));
        let mut out = Vec::new();
        io::copy(&mut r, &mut out).map_err(|_| OpenPgpError::MalformedMessage)?;
        if out.is_empty() {
            return Err(OpenPgpError::MalformedMessage);
        }
        Ok(out)
    }

    fn test_passphrase(&self, private_key: &[u8], passphrase: Option<&str>) -> Result<()> {
        let cert = parse_cert(private_key)?;
        reject_librepgp(&cert)?;
        if !cert.is_tsk() {
            return Err(OpenPgpError::InvalidKey("no secret key material".into()));
        }
        let password = passphrase.filter(|s| !s.is_empty()).map(Password::from);
        let mut unlocked_any = false;
        for ka in cert.keys().secret() {
            let key = ka.key().clone();
            let unlocked = if key.has_unencrypted_secret() {
                key
            } else {
                let Some(ref pw) = password else {
                    return Err(OpenPgpError::InvalidArgument(
                        "passphrase required".into(),
                    ));
                };
                key.decrypt_secret(pw)
                    .map_err(|_| OpenPgpError::DecryptionFailed)?
            };
            unlocked
                .into_keypair()
                .map_err(|_| OpenPgpError::DecryptionFailed)?;
            unlocked_any = true;
        }
        if !unlocked_any {
            return Err(OpenPgpError::InvalidKey("no secret keys".into()));
        }
        Ok(())
    }

    fn pop_sign_composite(
        &self,
        data: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        pop::pop_sign_composite(data, private_key, passphrase)
    }

    fn pop_hybrid_shared(
        &self,
        private_key: &[u8],
        passphrase: Option<&str>,
        kem_ciphertext: &[u8],
        ephemeral_x25519: &[u8],
    ) -> Result<Vec<u8>> {
        pop::pop_hybrid_shared(
            private_key,
            passphrase,
            kem_ciphertext,
            ephemeral_x25519,
        )
    }
}

fn maybe_armor<'a>(
    message: Message<'a>,
    armored: bool,
    kind: SequoiaArmorKind,
) -> Result<Message<'a>> {
    if !armored {
        return Ok(message);
    }
    Armorer::new(message)
        .kind(kind)
        .build()
        .map_err(|e| OpenPgpError::Internal(e.to_string()))
}

fn encrypt_message(
    plaintext: &[u8],
    recipient_public_keys: &[&[u8]],
    signing: Option<sequoia_openpgp::crypto::KeyPair>,
    options: &EncryptOptions,
) -> Result<Vec<u8>> {
    if recipient_public_keys.is_empty() {
        return Err(OpenPgpError::InvalidArgument(
            "at least one recipient public key is required".into(),
        ));
    }
    let p = generate_policy();
    let certs: Vec<Cert> = recipient_public_keys
        .iter()
        .map(|b| {
            let c = parse_cert(b)?;
            reject_librepgp(&c)?;
            Ok(c)
        })
        .collect::<Result<Vec<_>>>()?;

    let recipients: Vec<_> = certs
        .iter()
        .flat_map(|cert| {
            cert.keys()
                .with_policy(&p, None)
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
        })
        .collect();
    if recipients.is_empty() {
        return Err(OpenPgpError::NoSuitableEncryptionKey);
    }

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = maybe_armor(message, options.armored, SequoiaArmorKind::Message)?;
        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
        let message = if let Some(keypair) = signing {
            Signer::new(message, keypair)
                .map_err(|e| OpenPgpError::Internal(e.to_string()))?
                .build()
                .map_err(|e| OpenPgpError::Internal(e.to_string()))?
        } else {
            message
        };
        let mut literal = LiteralWriter::new(message)
            .build()
            .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
        literal
            .write_all(plaintext)
            .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
        literal
            .finalize()
            .map_err(|e| OpenPgpError::Internal(e.to_string()))?;
    }
    Ok(sink)
}

fn signing_keypair(
    cert: &Cert,
    passphrase: Option<&str>,
    p: &StandardPolicy<'_>,
) -> Result<(
    sequoia_openpgp::crypto::KeyPair,
    OpenPgpFingerprint,
    OpenPgpKeyId,
)> {
    let password = passphrase
        .filter(|s| !s.is_empty())
        .map(Password::from);
    for ka in cert
        .keys()
        .secret()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
    {
        let key = ka.key().clone();
        let unlocked = if let Some(ref pw) = password {
            match key.decrypt_secret(pw) {
                Ok(k) => k,
                Err(_) => continue,
            }
        } else {
            key
        };
        if let Ok(pair) = unlocked.into_keypair() {
            return Ok((
                pair,
                fingerprint_of(ka.key().fingerprint()),
                key_id_of(&ka.key().keyid()),
            ));
        }
    }
    Err(OpenPgpError::NoSuitableSigningKey)
}

pub(crate) fn parse_cert(bytes: &[u8]) -> Result<Cert> {
    if let Ok(cert) = Cert::from_bytes(bytes) {
        return Ok(cert);
    }
    let mut r = armor::Reader::from_reader(bytes, armor::ReaderMode::Tolerant(None));
    let mut bin = Vec::new();
    io::copy(&mut r, &mut bin).map_err(|_| OpenPgpError::InvalidKey("not an OpenPGP cert".into()))?;
    Cert::from_bytes(&bin).map_err(|e| OpenPgpError::InvalidKey(e.to_string()))
}

pub(crate) fn reject_librepgp(cert: &Cert) -> Result<()> {
    for key in cert.keys() {
        let id = u8::from(key.key().pk_algo());
        if id == ALG_LIBREPGP_KYBER_768 || id == ALG_LIBREPGP_KYBER_1024 {
            return Err(OpenPgpError::LibrePgpKyber);
        }
        let _ = PublicKeyAlgorithm::from(id);
    }
    Ok(())
}

pub(crate) fn catalog_name(algo: PublicKeyAlgorithm) -> String {
    match u8::from(algo) {
        22 => "openpgp-ed25519".into(),
        18 => "openpgp-cv25519".into(),
        ALG_ML_DSA_65_ED25519 => "openpgp-mldsa65-ed25519".into(),
        ALG_ML_KEM_768_X25519 => "openpgp-mlkem768-x25519".into(),
        1 | 2 | 3 => "openpgp-rsa".into(),
        other => format!("openpgp-pk-{other}"),
    }
}

pub(crate) fn fingerprint_of(fp: sequoia_openpgp::Fingerprint) -> OpenPgpFingerprint {
    OpenPgpFingerprint(fp.as_bytes().to_vec())
}

pub(crate) fn key_id_of(id: &sequoia_openpgp::KeyID) -> OpenPgpKeyId {
    OpenPgpKeyId(id.as_bytes().to_vec())
}

pub(crate) fn key_id_from_handle(h: &KeyHandle) -> OpenPgpKeyId {
    match h {
        KeyHandle::KeyID(id) => key_id_of(id),
        KeyHandle::Fingerprint(fp) => {
            let b = fp.as_bytes();
            let n = b.len().min(8);
            OpenPgpKeyId(b[b.len().saturating_sub(n)..].to_vec())
        }
    }
}
