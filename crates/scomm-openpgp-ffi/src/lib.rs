//! C ABI. Sequoia types do not cross this boundary.

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;
use serde_json::{json, Value};

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn engine() -> SequoiaOpenPgp {
    SequoiaOpenPgp::new()
}

fn set_error(msg: String) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(msg));
}

fn clear_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

unsafe fn write_buf(bytes: &[u8], out: *mut *mut u8, out_len: *mut usize) {
    if bytes.is_empty() {
        *out = ptr::null_mut();
        *out_len = 0;
        return;
    }
    let boxed = bytes.to_vec().into_boxed_slice();
    let len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    *out_len = len;
}

unsafe fn read_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        slice::from_raw_parts(ptr, len)
    }
}

fn usage_str(u: OpenPgpKeyUsage) -> &'static str {
    match u {
        OpenPgpKeyUsage::Signing => "signing",
        OpenPgpKeyUsage::Encryption => "encryption",
        OpenPgpKeyUsage::Authentication => "authentication",
        OpenPgpKeyUsage::Certification => "certification",
    }
}

fn key_info_json(info: &OpenPgpKeyInfo) -> String {
    let identities: Vec<Value> = info
        .identities
        .iter()
        .map(|i| {
            json!({
                "name": i.name,
                "email": i.email,
            })
        })
        .collect();
    let subkeys: Vec<Value> = info
        .subkeys
        .iter()
        .map(|s| {
            json!({
                "fingerprint": s.fingerprint.to_hex(),
                "key_id": s.key_id.to_hex(),
                "algorithm": s.algorithm,
                "algorithm_id": s.algorithm_id,
                "capabilities": s.capabilities.iter().map(|c| usage_str(*c)).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "fingerprint": info.fingerprint.to_hex(),
        "key_id": info.key_id.to_hex(),
        "algorithm": info.algorithm,
        "algorithm_id": info.algorithm_id,
        "is_pqc": info.is_pqc(),
        "is_pqc_signing": info.is_pqc_signing(),
        "created_at": info.created_at,
        "expires_at": info.expires_at,
        "revoked": info.revoked,
        "has_secret": info.has_secret,
        "secret_encrypted": info.secret_encrypted,
        "capabilities": info.capabilities.iter().map(|c| usage_str(*c)).collect::<Vec<_>>(),
        "identities": identities,
        "subkeys": subkeys,
    })
    .to_string()
}

fn map_err(e: OpenPgpError) -> i32 {
    set_error(e.to_string());
    e.code()
}

fn run(f: impl FnOnce() -> Result<i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => map_err(e),
        Err(_) => {
            set_error("panic in scomm-openpgp".into());
            OpenPgpError::Internal("panic".into()).code()
        }
    }
}

/// Recipients: u32be count, then repeating (u32be len + bytes).
fn parse_recipients(buf: &[u8]) -> Result<Vec<Vec<u8>>> {
    if buf.len() < 4 {
        return Err(OpenPgpError::InvalidArgument("recipients buffer".into()));
    }
    let n = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
    let mut i = 4;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if i + 4 > buf.len() {
            return Err(OpenPgpError::InvalidArgument("truncated recipient".into()));
        }
        let len = u32::from_be_bytes(buf[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + len > buf.len() {
            return Err(OpenPgpError::InvalidArgument("truncated recipient key".into()));
        }
        out.push(buf[i..i + len].to_vec());
        i += len;
    }
    Ok(out)
}

fn armor_kind(kind: i32) -> Result<ArmorKind> {
    match kind {
        0 => Ok(ArmorKind::PublicKey),
        1 => Ok(ArmorKind::SecretKey),
        2 => Ok(ArmorKind::Signature),
        3 => Ok(ArmorKind::Message),
        _ => Err(OpenPgpError::InvalidArgument("armor kind".into())),
    }
}

#[no_mangle]
pub extern "C" fn scomm_openpgp_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_buffer_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    drop(Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len)));
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_last_error(
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let msg = LAST_ERROR.with(|slot| slot.borrow().clone().unwrap_or_default());
    write_buf(msg.as_bytes(), out, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_inspect(
    key: *const u8,
    key_len: usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let key = read_slice(key, key_len).to_vec();
    run(|| {
        clear_error();
        let info = engine().inspect_key(&key)?;
        unsafe { write_buf(key_info_json(&info).as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_generate(
    userid: *const u8,
    userid_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    profile: i32,
    public_out: *mut *mut u8,
    public_len: *mut usize,
    secret_out: *mut *mut u8,
    secret_len: *mut usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let userid = String::from_utf8_lossy(read_slice(userid, userid_len)).into_owned();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    let profile = match profile {
        0 => KeyProfile::ClassicalCv25519,
        1 => KeyProfile::Rfc9980MlDsa65,
        _ => {
            set_error("unknown key profile".into());
            return OpenPgpError::InvalidArgument("profile".into()).code();
        }
    };
    run(|| {
        clear_error();
        let generated = engine().generate_key(&GenerateKeyOptions {
            userid,
            passphrase: pass,
            profile,
        })?;
        unsafe {
            write_buf(&generated.public, public_out, public_len);
            write_buf(&generated.secret, secret_out, secret_len);
            write_buf(key_info_json(&generated.info).as_bytes(), json_out, json_len);
        }
        Ok(0)
    })
}

#[no_mangle]
pub extern "C" fn scomm_openpgp_rfc9980_ready() -> i32 {
    if engine().rfc9980_ready() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_export_public(
    key: *const u8,
    key_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let key = read_slice(key, key_len).to_vec();
    run(|| {
        clear_error();
        let public = engine().export_public_key(&key)?;
        unsafe { write_buf(&public, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_armor(
    kind: i32,
    binary: *const u8,
    binary_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let binary = read_slice(binary, binary_len).to_vec();
    run(|| {
        clear_error();
        let armored = engine().armor(armor_kind(kind)?, &binary)?;
        unsafe { write_buf(&armored, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    recipients: *const u8,
    recipients_len: usize,
    armored: i32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let plaintext = read_slice(plaintext, plaintext_len).to_vec();
    let recipients = read_slice(recipients, recipients_len).to_vec();
    run(|| {
        clear_error();
        let recips = parse_recipients(&recipients)?;
        let refs: Vec<&[u8]> = recips.iter().map(|v| v.as_slice()).collect();
        let ct = engine().encrypt(
            &plaintext,
            &refs,
            &EncryptOptions {
                armored: armored != 0,
            },
        )?;
        unsafe { write_buf(&ct, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let ciphertext = read_slice(ciphertext, ciphertext_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        let pt = engine().decrypt(&ciphertext, &private_key, pass.as_deref())?;
        unsafe { write_buf(&pt.plaintext, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_sign(
    data: *const u8,
    data_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    armored: i32,
    detached: i32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        let sig = engine().sign(
            &data,
            &private_key,
            pass.as_deref(),
            &SignOptions {
                armored: armored != 0,
                detached: detached != 0,
            },
        )?;
        unsafe { write_buf(&sig.bytes, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_verify(
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    valid_out: *mut i32,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let signature = read_slice(signature, signature_len).to_vec();
    let public_key = read_slice(public_key, public_key_len).to_vec();
    run(|| {
        clear_error();
        let v = engine().verify(&data, &signature, &public_key)?;
        let ok = v.validity == SignatureValidity::CryptographicallyValid;
        unsafe { *valid_out = if ok { 1 } else { 0 } };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_test_passphrase(
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
) -> i32 {
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        engine().test_passphrase(&private_key, pass.as_deref())?;
        Ok(0)
    })
}
