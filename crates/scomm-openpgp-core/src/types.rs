/// Full OpenPGP fingerprint (v4: 20 bytes, v6: 32 bytes). Never a UI short id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpenPgpFingerprint(pub Vec<u8>);

impl OpenPgpFingerprint {
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

/// OpenPGP Key ID bytes (typically 8). Not a truncated display label.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpenPgpKeyId(pub Vec<u8>);

impl OpenPgpKeyId {
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPgpIdentity {
    pub name: Option<String>,
    pub email: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenPgpKeyUsage {
    Signing,
    Encryption,
    Authentication,
    Certification,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPgpSubkeyInfo {
    pub fingerprint: OpenPgpFingerprint,
    pub key_id: OpenPgpKeyId,
    pub algorithm: String,
    /// OpenPGP public-key algorithm ID (RFC 9580 / 9980).
    pub algorithm_id: u8,
    pub capabilities: Vec<OpenPgpKeyUsage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPgpKeyInfo {
    pub fingerprint: OpenPgpFingerprint,
    pub key_id: OpenPgpKeyId,
    pub identities: Vec<OpenPgpIdentity>,
    /// Catalog-style name when known (`openpgp-ed25519`, `openpgp-mlkem768-x25519`).
    pub algorithm: String,
    /// OpenPGP public-key algorithm ID of the primary key.
    pub algorithm_id: u8,
    pub created_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub capabilities: Vec<OpenPgpKeyUsage>,
    pub has_secret: bool,
    /// True when any secret key packet is passphrase-protected.
    pub secret_encrypted: bool,
    pub subkeys: Vec<OpenPgpSubkeyInfo>,
}

impl OpenPgpKeyInfo {
    /// RFC 9980 composite (IDs 30 / 35) on the primary or any subkey.
    pub fn is_pqc(&self) -> bool {
        is_rfc9980_id(self.algorithm_id)
            || self.subkeys.iter().any(|s| is_rfc9980_id(s.algorithm_id))
    }

    pub fn is_pqc_signing(&self) -> bool {
        (30..=34).contains(&self.algorithm_id) || is_pqc_signing_catalog(&self.algorithm)
    }
}

pub fn is_rfc9980_id(id: u8) -> bool {
    (30..=36).contains(&id)
}

pub fn is_pqc_signing_catalog(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "openpgp-mldsa65-ed25519"
            | "openpgp-mldsa87-ed448"
            | "openpgp-slhdsa-shake128s"
            | "openpgp-slhdsa-shake128f"
            | "openpgp-slhdsa-shake256s"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProfile {
    /// Ed25519 certification/signing + X25519 encryption (v4). Interop default
    /// for clients that cannot read RFC 9580.
    ClassicalCv25519,
    /// RFC 9980 MUST: ML-DSA-65+Ed25519 primary + ML-KEM-768+X25519 subkey (v6).
    Rfc9980MlDsa65,
    /// RFC 9580 Ed25519 primary + X25519 encryption subkey (v6).
    Rfc9580Cv25519,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateKeyOptions {
    pub userid: String,
    pub passphrase: Option<String>,
    pub profile: KeyProfile,
}

impl Default for GenerateKeyOptions {
    fn default() -> Self {
        Self {
            userid: String::new(),
            passphrase: None,
            profile: KeyProfile::ClassicalCv25519,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
    pub info: OpenPgpKeyInfo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignOptions {
    pub armored: bool,
    pub detached: bool,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            armored: false,
            detached: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignatureResult {
    pub bytes: Vec<u8>,
    pub fingerprint: OpenPgpFingerprint,
    pub key_id: OpenPgpKeyId,
}

/// Cryptographic validity only. Trust is the caller's decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureValidity {
    CryptographicallyValid,
    CryptographicallyInvalid,
    UnknownSigner,
    MalformedSignature,
    UnsupportedAlgorithm,
}

#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub validity: SignatureValidity,
    pub signer_fingerprint: Option<OpenPgpFingerprint>,
    pub signer_key_id: Option<OpenPgpKeyId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptOptions {
    pub armored: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self { armored: false }
    }
}

#[derive(Clone, Debug)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub recipient_key_id: Option<OpenPgpKeyId>,
}

#[derive(Clone, Debug)]
pub struct SignatureInfo {
    pub fingerprint: Option<OpenPgpFingerprint>,
    pub key_id: Option<OpenPgpKeyId>,
    pub validity: SignatureValidity,
    pub created_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct DecryptVerifyResult {
    pub plaintext: Vec<u8>,
    pub recipient_key_id: Option<OpenPgpKeyId>,
    pub signatures: Vec<SignatureInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct MessageInfo {
    pub encrypted: bool,
    pub signed: bool,
    pub armored: bool,
    pub recipient_key_ids: Vec<OpenPgpKeyId>,
    pub signature_key_ids: Vec<OpenPgpKeyId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmorKind {
    PublicKey,
    SecretKey,
    Signature,
    Message,
}
