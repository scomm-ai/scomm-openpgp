use crate::error::{OpenPgpError, Result};
use crate::types::*;

/// Bytes-in / bytes-out OpenPGP operations. No vault, network, or filesystem.
pub trait OpenPgpProvider: Send + Sync {
    fn inspect_key(&self, key: &[u8]) -> Result<OpenPgpKeyInfo>;

    fn generate_key(&self, options: &GenerateKeyOptions) -> Result<GeneratedKey>;

    /// True when this backend can generate and use RFC 9980 MUST algorithms.
    fn rfc9980_ready(&self) -> bool {
        false
    }

    fn export_public_key(&self, secret_or_public: &[u8]) -> Result<Vec<u8>>;

    fn sign(
        &self,
        data: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
        options: &SignOptions,
    ) -> Result<SignatureResult>;

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<VerificationResult>;

    fn encrypt(
        &self,
        plaintext: &[u8],
        recipient_public_keys: &[&[u8]],
        options: &EncryptOptions,
    ) -> Result<Vec<u8>>;

    fn decrypt(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
    ) -> Result<DecryptResult>;

    fn encrypt_and_sign(
        &self,
        plaintext: &[u8],
        recipient_public_keys: &[&[u8]],
        signing_private_key: &[u8],
        passphrase: Option<&str>,
        options: &EncryptOptions,
    ) -> Result<Vec<u8>>;

    fn decrypt_and_verify(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
        signer_public_keys: &[&[u8]],
    ) -> Result<DecryptVerifyResult>;

    fn inspect_message(&self, message: &[u8]) -> Result<MessageInfo>;

    fn armor(&self, kind: ArmorKind, binary: &[u8]) -> Result<Vec<u8>>;

    fn dearmor(&self, armored: &[u8]) -> Result<Vec<u8>>;

    /// Unlocks secret key material with [passphrase] (empty/none if unprotected).
    fn test_passphrase(&self, private_key: &[u8], passphrase: Option<&str>) -> Result<()>;

    /// Detached OpenPGP signature over [data] with a critical notation.
    /// Used as proof of possession so the key stays inside OpenPGP.
    fn sign_pop(
        &self,
        data: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
        notation: &str,
    ) -> Result<Vec<u8>> {
        let _ = (data, private_key, passphrase, notation);
        Err(OpenPgpError::UnsupportedAlgorithm(
            "openpgp artifact PoP signing".into(),
        ))
    }

    /// `mlkem_shared || x25519_shared` for hybrid encrypt PoP (caller SHA-256s like the server).
    /// 32-byte Ed25519 seed (`signing`) or X25519 secret from an unlocked key.
    fn export_curve_secret(
        &self,
        private_key: &[u8],
        passphrase: Option<&str>,
        signing: bool,
    ) -> Result<Vec<u8>> {
        let _ = (private_key, passphrase, signing);
        Err(OpenPgpError::UnsupportedAlgorithm(
            "curve25519 secret export".into(),
        ))
    }

}
