//! Shared primitives on the one libcrypto. AES-GCM uses Crypter
//! (EVP_EncryptUpdate / EVP_DecryptUpdate), never EVP_Cipher.

use openssl::hash::{hash, MessageDigest};
use openssl::kdf::argon2id;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{Cipher, Crypter, Mode};
use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use ossl::signature::{OsslSignature, SigAlg, SigOp};
use ossl::OsslSecret;

fn ctx() -> ossl::OsslContext {
    ossl::OsslContext::new_lib_ctx()
}

pub fn sha256(data: &[u8]) -> Result<Vec<u8>, String> {
    hash(MessageDigest::sha256(), data)
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

pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let key = PKey::public_key_from_raw_bytes(public, openssl::pkey::Id::ED25519)
        .map_err(|e| e.to_string())?;
    let mut verifier = Verifier::new_without_digest(&key).map_err(|e| e.to_string())?;
    verifier.verify_oneshot(signature, message).map_err(|e| e.to_string())
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
