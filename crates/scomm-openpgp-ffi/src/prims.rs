//! Shared primitives on the one libcrypto. AES-GCM uses Crypter
//! (EVP_EncryptUpdate / EVP_DecryptUpdate), never EVP_Cipher.

use openssl::hash::{hash, MessageDigest};
use openssl::kdf::argon2id;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509ReqBuilder};
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{Cipher, Crypter, Mode};
use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use ossl::signature::{OsslSignature, SigAlg, SigOp};
use ossl::OsslSecret;

fn init() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        // OPENSSL_INIT_NO_LOAD_CONFIG (0x80) is not exported by openssl-sys.
        openssl_sys::OPENSSL_init_crypto(
            0x80 | openssl_sys::OPENSSL_INIT_NO_ATEXIT,
            std::ptr::null_mut(),
        );
        // Argon2id lanes run only when the libctx thread cap is at least `p`.
        openssl_sys::OSSL_set_max_threads(std::ptr::null_mut(), 4);
    });
}

fn ctx() -> ossl::OsslContext {
    init();
    ossl::OsslContext::new_lib_ctx()
}

pub fn sha256(data: &[u8]) -> Result<Vec<u8>, String> {
    init();
    hash(MessageDigest::sha256(), data)
        .map(|d| d.to_vec())
        .map_err(|e| e.to_string())
}

pub fn sha512(data: &[u8]) -> Result<Vec<u8>, String> {
    init();
    hash(MessageDigest::sha512(), data)
        .map(|d| d.to_vec())
        .map_err(|e| e.to_string())
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let pkey = PKey::hmac(key).map_err(|e| e.to_string())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).map_err(|e| e.to_string())?;
    signer.update(data).map_err(|e| e.to_string())?;
    signer.sign_to_vec().map_err(|e| e.to_string())
}

pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    out_len: usize,
) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; out_len];
    pbkdf2_hmac(password, salt, iterations, MessageDigest::sha256(), &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    lanes: u32,
    mem_kib: u32,
    out_len: usize,
) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; out_len];
    argon2id(None, password, salt, None, None, iterations, lanes, mem_kib, &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Digest ids shared with the C ABI: 1 MD5, 2 SHA-1, 3 SHA-256, 4 SHA-384, 5 SHA-512.
fn digest_by_id(id: i32) -> Result<MessageDigest, String> {
    init();
    match id {
        1 => Ok(MessageDigest::md5()),
        2 => Ok(MessageDigest::sha1()),
        3 => Ok(MessageDigest::sha256()),
        4 => Ok(MessageDigest::sha384()),
        5 => Ok(MessageDigest::sha512()),
        _ => Err("digest id".into()),
    }
}

pub fn digest(id: i32, data: &[u8]) -> Result<Vec<u8>, String> {
    hash(digest_by_id(id)?, data)
        .map(|d| d.to_vec())
        .map_err(|e| e.to_string())
}

pub fn hmac(id: i32, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let md = digest_by_id(id)?;
    let pkey = PKey::hmac(key).map_err(|e| e.to_string())?;
    let mut signer = Signer::new(md, &pkey).map_err(|e| e.to_string())?;
    signer.update(data).map_err(|e| e.to_string())?;
    signer.sign_to_vec().map_err(|e| e.to_string())
}

pub fn pbkdf2(
    id: i32,
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    out_len: usize,
) -> Result<Vec<u8>, String> {
    let md = digest_by_id(id)?;
    let mut out = vec![0u8; out_len];
    pbkdf2_hmac(password, salt, iterations, md, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// RSASSA-PKCS1-v1_5. `pkcs8` is a PKCS#8 (or PKCS#1) DER private key.
pub fn rsa_pkcs1_sign(id: i32, pkcs8: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let md = digest_by_id(id)?;
    let key = PKey::private_key_from_der(pkcs8).map_err(|e| e.to_string())?;
    if key.id() != openssl::pkey::Id::RSA {
        return Err("rsa key".into());
    }
    let mut signer = Signer::new(md, &key).map_err(|e| e.to_string())?;
    signer.update(message).map_err(|e| e.to_string())?;
    signer.sign_to_vec().map_err(|e| e.to_string())
}

/// `spki` is a SubjectPublicKeyInfo DER. A bad signature is `Ok(false)`.
pub fn rsa_pkcs1_verify(
    id: i32,
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let md = digest_by_id(id)?;
    let key = PKey::public_key_from_der(spki).map_err(|e| e.to_string())?;
    if key.id() != openssl::pkey::Id::RSA {
        return Err("rsa key".into());
    }
    let mut verifier = Verifier::new(md, &key).map_err(|e| e.to_string())?;
    verifier.update(message).map_err(|e| e.to_string())?;
    Ok(verifier.verify(signature).unwrap_or(false))
}

/// ECDSA over a SubjectPublicKeyInfo DER key. `raw` signatures are the JWS
/// `r || s` form (equal halves); otherwise ASN.1 DER.
pub fn ecdsa_verify(
    id: i32,
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
    raw: bool,
) -> Result<bool, String> {
    let md = digest_by_id(id)?;
    let key = PKey::public_key_from_der(spki).map_err(|e| e.to_string())?;
    if key.id() != openssl::pkey::Id::EC {
        return Err("ec key".into());
    }
    let der = if raw {
        if signature.is_empty() || signature.len() % 2 != 0 {
            return Ok(false);
        }
        let half = signature.len() / 2;
        let r = BigNum::from_slice(&signature[..half]).map_err(|e| e.to_string())?;
        let s = BigNum::from_slice(&signature[half..]).map_err(|e| e.to_string())?;
        EcdsaSig::from_private_components(r, s)
            .and_then(|sig| sig.to_der())
            .map_err(|e| e.to_string())?
    } else {
        signature.to_vec()
    };
    let mut verifier = Verifier::new(md, &key).map_err(|e| e.to_string())?;
    verifier.update(message).map_err(|e| e.to_string())?;
    Ok(verifier.verify(&der).unwrap_or(false))
}

fn aes_cbc_cipher(key: &[u8]) -> Result<Cipher, String> {
    match key.len() {
        16 => Ok(Cipher::aes_128_cbc()),
        24 => Ok(Cipher::aes_192_cbc()),
        32 => Ok(Cipher::aes_256_cbc()),
        _ => Err("aes key".into()),
    }
}

/// AES-CBC with PKCS#7 padding.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    openssl::symm::encrypt(aes_cbc_cipher(key)?, key, Some(iv), plaintext)
        .map_err(|e| e.to_string())
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    openssl::symm::decrypt(aes_cbc_cipher(key)?, key, Some(iv), ciphertext)
        .map_err(|_| "aes-cbc".to_string())
}

/// Key kinds shared with the C ABI: 1 EC P-256, 2 RSA-2048, 3 RSA-3072, 4 Ed25519.
/// Returns (PKCS#8 PrivateKeyInfo DER, SubjectPublicKeyInfo DER).
pub fn pkey_generate(kind: i32) -> Result<(Vec<u8>, Vec<u8>), String> {
    init();
    let key = match kind {
        1 => {
            let group =
                EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| e.to_string())?;
            let ec = EcKey::generate(&group).map_err(|e| e.to_string())?;
            PKey::from_ec_key(ec).map_err(|e| e.to_string())?
        }
        2 | 3 => {
            let bits = if kind == 2 { 2048 } else { 3072 };
            let rsa = Rsa::generate(bits).map_err(|e| e.to_string())?;
            PKey::from_rsa(rsa).map_err(|e| e.to_string())?
        }
        4 => PKey::generate_ed25519().map_err(|e| e.to_string())?,
        _ => return Err("key kind".into()),
    };
    key_der(&key)
}

fn key_der(key: &PKey<openssl::pkey::Private>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pkcs8 = key.private_key_to_pkcs8().map_err(|e| e.to_string())?;
    let spki = key.public_key_to_der().map_err(|e| e.to_string())?;
    Ok((pkcs8, spki))
}

/// EC P-256 key pair from a 32-byte private scalar (public point recomputed).
pub fn ec_p256_from_scalar(d: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    init();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| e.to_string())?;
    let d = BigNum::from_slice(d).map_err(|e| e.to_string())?;
    let ctx = BigNumContext::new().map_err(|e| e.to_string())?;
    let mut point = EcPoint::new(&group).map_err(|e| e.to_string())?;
    point
        .mul_generator(&group, &d, &ctx)
        .map_err(|e| e.to_string())?;
    let ec = EcKey::from_private_components(&group, &d, &point).map_err(|e| e.to_string())?;
    key_der(&PKey::from_ec_key(ec).map_err(|e| e.to_string())?)
}

/// SubjectPublicKeyInfo DER of a PKCS#8 private key.
pub fn pkcs8_public_spki(pkcs8: &[u8]) -> Result<Vec<u8>, String> {
    init();
    PKey::private_key_from_der(pkcs8)
        .and_then(|key| key.public_key_to_der())
        .map_err(|e| e.to_string())
}

/// Schemes: 1 ECDSA-SHA256 (ASN.1 DER), 2 RSASSA-PKCS1-v1_5-SHA256, 3 Ed25519.
pub fn pkey_sign(scheme: i32, pkcs8: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    init();
    let key = PKey::private_key_from_der(pkcs8).map_err(|e| e.to_string())?;
    match scheme {
        1 | 2 => {
            let want = if scheme == 1 {
                openssl::pkey::Id::EC
            } else {
                openssl::pkey::Id::RSA
            };
            if key.id() != want {
                return Err("key type".into());
            }
            let mut signer =
                Signer::new(MessageDigest::sha256(), &key).map_err(|e| e.to_string())?;
            signer.update(message).map_err(|e| e.to_string())?;
            signer.sign_to_vec().map_err(|e| e.to_string())
        }
        3 => {
            if key.id() != openssl::pkey::Id::ED25519 {
                return Err("key type".into());
            }
            let mut signer = Signer::new_without_digest(&key).map_err(|e| e.to_string())?;
            signer
                .sign_oneshot_to_vec(message)
                .map_err(|e| e.to_string())
        }
        _ => Err("sign scheme".into()),
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend([0x81, n as u8]);
    } else if n < 0x10000 {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn der_uint(v: u32) -> Vec<u8> {
    let mut bytes: Vec<u8> = v
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der(0x02, &bytes)
}

const OID_PBES2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
const OID_PBKDF2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
const OID_HMAC_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A];

/// PKCS#8 PrivateKeyInfo -> EncryptedPrivateKeyInfo (PBES2, PBKDF2-HMAC-SHA256,
/// AES-256-CBC) with the given iteration count.
pub fn pkcs8_encrypt(pkcs8: &[u8], passphrase: &[u8], iterations: u32) -> Result<Vec<u8>, String> {
    init();
    if iterations == 0 {
        return Err("iterations".into());
    }
    let salt = random(16)?;
    let iv = random(16)?;
    let key = pbkdf2_hmac_sha256(passphrase, &salt, iterations as usize, 32)?;
    let encrypted = aes_cbc_encrypt(&key, &iv, pkcs8)?;

    let prf = der(0x30, &[der(0x06, OID_HMAC_SHA256), vec![0x05, 0x00]].concat());
    let kdf_params = der(0x30, &[der(0x04, &salt), der_uint(iterations), prf].concat());
    let kdf = der(0x30, &[der(0x06, OID_PBKDF2), kdf_params].concat());
    let scheme = der(0x30, &[der(0x06, OID_AES256_CBC), der(0x04, &iv)].concat());
    let pbes2 = der(
        0x30,
        &[der(0x06, OID_PBES2), der(0x30, &[kdf, scheme].concat())].concat(),
    );
    Ok(der(0x30, &[pbes2, der(0x04, &encrypted)].concat()))
}

/// Any OpenSSL-readable EncryptedPrivateKeyInfo DER -> PKCS#8 PrivateKeyInfo DER.
pub fn pkcs8_decrypt(encrypted: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
    init();
    let key = PKey::private_key_from_pkcs8_passphrase(encrypted, passphrase)
        .map_err(|_| "pkcs8 passphrase".to_string())?;
    key.private_key_to_pkcs8().map_err(|e| e.to_string())
}

/// PKCS#10 CertificationRequest DER for a PKCS#8 key. `subject` is `CN=..,O=..`.
pub fn csr_create(pkcs8: &[u8], subject: &str) -> Result<Vec<u8>, String> {
    init();
    let key = PKey::private_key_from_der(pkcs8).map_err(|e| e.to_string())?;
    let mut name = X509NameBuilder::new().map_err(|e| e.to_string())?;
    let mut any = false;
    for part in subject.split(',') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let nid = match k.trim().to_uppercase().as_str() {
            "O" => Nid::ORGANIZATIONNAME,
            "OU" => Nid::ORGANIZATIONALUNITNAME,
            "C" => Nid::COUNTRYNAME,
            "L" => Nid::LOCALITYNAME,
            "ST" => Nid::STATEORPROVINCENAME,
            _ => Nid::COMMONNAME,
        };
        name.append_entry_by_nid(nid, v.trim())
            .map_err(|e| e.to_string())?;
        any = true;
    }
    if !any {
        name.append_entry_by_nid(Nid::COMMONNAME, subject)
            .map_err(|e| e.to_string())?;
    }
    let name = name.build();
    let mut req = X509ReqBuilder::new().map_err(|e| e.to_string())?;
    req.set_subject_name(&name).map_err(|e| e.to_string())?;
    req.set_pubkey(&key).map_err(|e| e.to_string())?;
    let md = if key.id() == openssl::pkey::Id::ED25519 {
        MessageDigest::null()
    } else {
        MessageDigest::sha256()
    };
    req.sign(&key, md).map_err(|e| e.to_string())?;
    req.build().to_der().map_err(|e| e.to_string())
}

pub fn random(n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    rand_bytes(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

pub fn aes256gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), String> {
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, key, Some(nonce))
        .map_err(|e| e.to_string())?;
    crypter.pad(false);
    if !aad.is_empty() {
        crypter.aad_update(aad).map_err(|e| e.to_string())?;
    }
    let mut out = vec![0u8; plaintext.len() + 32];
    let mut n = crypter.update(plaintext, &mut out).map_err(|e| e.to_string())?;
    n += crypter.finalize(&mut out[n..]).map_err(|e| e.to_string())?;
    out.truncate(n);
    let mut tag = [0u8; 16];
    crypter.get_tag(&mut tag).map_err(|e| e.to_string())?;
    Ok((out, tag))
}

pub fn aes256gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, String> {
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(nonce))
        .map_err(|e| e.to_string())?;
    crypter.pad(false);
    crypter.set_tag(tag).map_err(|e| e.to_string())?;
    if !aad.is_empty() {
        crypter.aad_update(aad).map_err(|e| e.to_string())?;
    }
    let mut out = vec![0u8; ciphertext.len() + 32];
    let mut n = crypter.update(ciphertext, &mut out).map_err(|e| e.to_string())?;
    n += crypter.finalize(&mut out[n..]).map_err(|_| "aes-gcm tag".to_string())?;
    out.truncate(n);
    Ok(out)
}

pub fn ed25519_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if seed.len() != 32 {
        return Err("ed25519 seed".into());
    }
    let secret = PKey::private_key_from_raw_bytes(seed, openssl::pkey::Id::ED25519)
        .map_err(|e| e.to_string())?;
    let public = secret.raw_public_key().map_err(|e| e.to_string())?;
    Ok((public, seed.to_vec()))
}

pub fn ed25519_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let secret = PKey::private_key_from_raw_bytes(seed, openssl::pkey::Id::ED25519)
        .map_err(|e| e.to_string())?;
    let mut signer = Signer::new_without_digest(&secret).map_err(|e| e.to_string())?;
    signer.sign_oneshot_to_vec(message).map_err(|e| e.to_string())
}

pub fn x25519_public(seed: &[u8]) -> Result<Vec<u8>, String> {
    if seed.len() != 32 {
        return Err("x25519 seed".into());
    }
    let secret = PKey::private_key_from_raw_bytes(seed, openssl::pkey::Id::X25519)
        .map_err(|e| e.to_string())?;
    secret.raw_public_key().map_err(|e| e.to_string())
}

pub fn x25519_dh(seed: &[u8], peer: &[u8]) -> Result<Vec<u8>, String> {
    let secret = PKey::private_key_from_raw_bytes(seed, openssl::pkey::Id::X25519)
        .map_err(|e| e.to_string())?;
    let public = PKey::public_key_from_raw_bytes(peer, openssl::pkey::Id::X25519)
        .map_err(|e| e.to_string())?;
    let mut deriver = openssl::derive::Deriver::new(&secret).map_err(|e| e.to_string())?;
    deriver.set_peer(&public).map_err(|e| e.to_string())?;
    deriver.derive_to_vec().map_err(|e| e.to_string())
}

pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let key = PKey::public_key_from_raw_bytes(public, openssl::pkey::Id::ED25519)
        .map_err(|e| e.to_string())?;
    let mut verifier = Verifier::new_without_digest(&key).map_err(|e| e.to_string())?;
    verifier.verify_oneshot(signature, message).map_err(|e| e.to_string())
}

pub fn mldsa65_public(seed: &[u8]) -> Result<Vec<u8>, String> {
    if seed.len() != 32 {
        return Err("ml-dsa seed".into());
    }
    let c = ctx();
    let key = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|e| e.to_string())?;
    match key.export().map_err(|e| e.to_string())? {
        PkeyData::Mlkey(MlkeyData { pubkey: Some(ref pk), .. }) => Ok(pk.clone()),
        _ => Err("ml-dsa public".into()),
    }
}

pub fn mldsa65_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    if public.len() != 1952 || signature.len() != 3309 {
        return Err("ml-dsa lengths".into());
    }
    let c = ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: Some(public.to_vec()),
            prikey: None,
            seed: None,
        }),
    )
    .map_err(|e| e.to_string())?;
    let mut verifier = OsslSignature::new(&c, SigOp::Verify, SigAlg::Mldsa65, &mut key, None)
        .map_err(|e| e.to_string())?;
    Ok(verifier
        .verify(message, Some(signature))
        .map_err(|e| e.to_string())
        .is_ok())
}

/// Seed is ML-DSA-65 (32) then Ed25519 (32). Signature is ML-DSA (3309) then Ed25519 (64).
pub fn msk_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    if seed.len() != 64 {
        return Err("msk seed".into());
    }
    let mut out = mldsa65_sign(&seed[..32], message)?;
    out.extend(ed25519_sign(&seed[32..], message)?);
    Ok(out)
}

pub fn msk_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    if public.len() != 1952 + 32 || signature.len() != 3309 + 64 {
        return Err("msk lengths".into());
    }
    let ml = mldsa65_verify(&public[..1952], message, &signature[..3309])?;
    let ed = ed25519_verify(&public[1952..], message, &signature[3309..])?;
    Ok(ml && ed)
}

pub fn mldsa65_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    if seed.len() != 32 {
        return Err("ml-dsa seed".into());
    }
    let c = ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|e| e.to_string())?;
    let mut signer = OsslSignature::new(&c, SigOp::Sign, SigAlg::Mldsa65, &mut key, None)
        .map_err(|e| e.to_string())?;
    let mut signature = vec![0u8; 3309];
    signer
        .sign(message, Some(&mut signature))
        .map_err(|e| e.to_string())?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        let dig = sha256(b"abc").unwrap();
        assert_eq!(
            hex::encode_simple(&dig),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn gcm_roundtrip_and_empty_wrong_tag() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let (ct, tag) = aes256gcm_encrypt(&key, &nonce, b"aad", b"hello").unwrap();
        let pt = aes256gcm_decrypt(&key, &nonce, b"aad", &ct, &tag).unwrap();
        assert_eq!(pt, b"hello");
        let (empty, tag) = aes256gcm_encrypt(&key, &nonce, b"", b"").unwrap();
        assert!(empty.is_empty());
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(aes256gcm_decrypt(&key, &nonce, b"", &empty, &bad).is_err());
    }

    #[test]
    fn kdf_and_random() {
        let dk = pbkdf2_hmac_sha256(b"pw", b"salt", 1, 32).unwrap();
        assert_eq!(dk.len(), 32);
        let ak = argon2id_derive(b"pw", b"saltsalt", 1, 1, 8192, 32).unwrap();
        assert_eq!(ak.len(), 32);
        assert_eq!(random(16).unwrap().len(), 16);
    }

    #[test]
    fn digests_and_hmac() {
        assert_eq!(
            hex::encode_simple(&digest(2, b"abc").unwrap()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode_simple(&digest(1, b"abc").unwrap()),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        // RFC 4231 test case 2
        assert_eq!(
            hex::encode_simple(&hmac(3, b"Jefe", b"what do ya want for nothing?").unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex::encode_simple(&pbkdf2(2, b"password", b"salt", 2, 20).unwrap()),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
    }

    #[test]
    fn rsa_pkcs1_roundtrip() {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        let pkcs8 = key.private_key_to_pkcs8().unwrap();
        let spki = key.public_key_to_der().unwrap();
        let sig = rsa_pkcs1_sign(3, &pkcs8, b"attrs").unwrap();
        assert_eq!(sig.len(), 256);
        assert!(rsa_pkcs1_verify(3, &spki, b"attrs", &sig).unwrap());
        assert!(!rsa_pkcs1_verify(3, &spki, b"other", &sig).unwrap());
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!rsa_pkcs1_verify(3, &spki, b"attrs", &bad).unwrap());
    }

    #[test]
    fn ecdsa_p256_raw_and_der() {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(ec.clone()).unwrap();
        let spki = key.public_key_to_der().unwrap();
        let sig = EcdsaSig::sign(&openssl::hash::hash(MessageDigest::sha256(), b"jwt").unwrap(), &ec)
            .unwrap();
        let der = sig.to_der().unwrap();
        assert!(ecdsa_verify(3, &spki, b"jwt", &der, false).unwrap());
        let mut raw = sig.r().to_vec_padded(32).unwrap();
        raw.extend(sig.s().to_vec_padded(32).unwrap());
        assert!(ecdsa_verify(3, &spki, b"jwt", &raw, true).unwrap());
        assert!(!ecdsa_verify(3, &spki, b"nope", &raw, true).unwrap());
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let key = [1u8; 32];
        let iv = [2u8; 16];
        let ct = aes_cbc_encrypt(&key, &iv, b"hello").unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(aes_cbc_decrypt(&key, &iv, &ct).unwrap(), b"hello");
    }

    #[test]
    fn pkey_generate_sign_and_csr() {
        for kind in 1..=4 {
            let (pkcs8, spki) = pkey_generate(kind).unwrap();
            let scheme = match kind {
                1 => 1,
                4 => 3,
                _ => 2,
            };
            let sig = pkey_sign(scheme, &pkcs8, b"msg").unwrap();
            let ok = match kind {
                1 => ecdsa_verify(3, &spki, b"msg", &sig, false).unwrap(),
                4 => {
                    let key = PKey::public_key_from_der(&spki).unwrap();
                    ed25519_verify(&key.raw_public_key().unwrap(), b"msg", &sig).unwrap()
                }
                _ => rsa_pkcs1_verify(3, &spki, b"msg", &sig).unwrap(),
            };
            assert!(ok, "kind {kind}");
            let csr = csr_create(&pkcs8, "CN=device,O=Example").unwrap();
            let req = openssl::x509::X509Req::from_der(&csr).unwrap();
            assert!(req.verify(&req.public_key().unwrap()).unwrap(), "csr {kind}");
        }
    }

    #[test]
    fn pkcs8_pbes2_roundtrip_and_wrong_passphrase() {
        let (pkcs8, _) = pkey_generate(1).unwrap();
        let enc = pkcs8_encrypt(&pkcs8, b"correct horse", 1000).unwrap();
        assert_eq!(pkcs8_decrypt(&enc, b"correct horse").unwrap(), pkcs8);
        assert!(pkcs8_decrypt(&enc, b"wrong").is_err());
    }

    #[test]
    fn ec_p256_scalar_matches_generated_public() {
        let (pkcs8, spki) = pkey_generate(1).unwrap();
        let key = PKey::private_key_from_der(&pkcs8).unwrap();
        let d = key
            .ec_key()
            .unwrap()
            .private_key()
            .to_vec_padded(32)
            .unwrap();
        let (_, spki_again) = ec_p256_from_scalar(&d).unwrap();
        assert_eq!(spki, spki_again);
    }

    #[test]
    fn msk_roundtrip() {
        let seed = [9u8; 64];
        let sig = msk_sign(&seed, b"canonical").unwrap();
        assert_eq!(sig.len(), 3309 + 64);
        let mut public = mldsa65_public(&seed[..32]).unwrap();
        public.extend(ed25519_from_seed(&seed[32..]).unwrap().0);
        assert!(msk_verify(&public, b"canonical", &sig).unwrap());
    }

    #[test]
    fn x25519_agreement() {
        let a = [4u8; 32];
        let b = [5u8; 32];
        let ap = x25519_public(&a).unwrap();
        let bp = x25519_public(&b).unwrap();
        assert_eq!(x25519_dh(&a, &bp).unwrap(), x25519_dh(&b, &ap).unwrap());
    }

    #[test]
    fn ed25519_roundtrip() {
        let seed = [3u8; 32];
        let (public, _) = ed25519_from_seed(&seed).unwrap();
        let sig = ed25519_sign(&seed, b"msg").unwrap();
        assert!(ed25519_verify(&public, b"msg", &sig).unwrap());
        assert!(!ed25519_verify(&public, b"nope", &sig).unwrap());
    }
}

mod hex {
    pub fn encode_simple(bytes: &[u8]) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 0xf) as usize] as char);
        }
        s
    }
}
