//! Shared primitives on the one libcrypto. AES-GCM uses Crypter
//! (EVP_EncryptUpdate / EVP_DecryptUpdate), never EVP_Cipher.

use openssl::hash::{hash, MessageDigest};
use openssl::kdf::argon2id;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::bn::BigNum;
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
