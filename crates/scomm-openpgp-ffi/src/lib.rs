//! C ABI. Sequoia types do not cross this boundary.

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

mod prims;

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
            return Err(OpenPgpError::InvalidArgument(
                "truncated recipient key".into(),
            ));
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
    let _ = scomm_smime::link_anchor();
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
pub unsafe extern "C" fn scomm_openpgp_last_error(out: *mut *mut u8, out_len: *mut usize) -> i32 {
    let msg = LAST_ERROR.with(|slot| slot.borrow().clone().unwrap_or_default());
    write_buf(msg.as_bytes(), out, out_len);
    0
}

/// Version text of the linked libcrypto, such as `OpenSSL 4.1.0 23 Oct 2026`.
#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_openssl_version(
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    write_buf(prims::openssl_version().as_bytes(), out, out_len);
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
    scomm_openpgp_generate_with_validity(
        userid,
        userid_len,
        passphrase,
        passphrase_len,
        profile,
        0,
        public_out,
        public_len,
        secret_out,
        secret_len,
        json_out,
        json_len,
    )
}

/// ABI 6. As `scomm_openpgp_generate`, valid for `validity_years` from now
/// (1 to 10). 0 keeps the engine's previous default lifetime.
#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_generate_with_validity(
    userid: *const u8,
    userid_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    profile: i32,
    validity_years: u32,
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
        2 => KeyProfile::Rfc9580Cv25519,
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
            validity_years: (validity_years != 0).then_some(validity_years),
        })?;
        unsafe {
            write_buf(&generated.public, public_out, public_len);
            write_buf(&generated.secret, secret_out, secret_len);
            write_buf(
                key_info_json(&generated.info).as_bytes(),
                json_out,
                json_len,
            );
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

/// Detached verification as JSON: `validity` (valid, invalid,
/// unknown-signer, malformed, unsupported), `signer_fingerprint`,
/// `signer_primary_fingerprint` (what pins use), `signer_key_id` (hex) and
/// `weak_algorithm`. Additive; [scomm_openpgp_verify] is unchanged.
#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_verify_detached(
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let signature = read_slice(signature, signature_len).to_vec();
    let public_key = read_slice(public_key, public_key_len).to_vec();
    *json_out = ptr::null_mut();
    *json_len = 0;
    run(|| {
        clear_error();
        let v = engine().verify(&data, &signature, &public_key)?;
        let validity = match v.validity {
            SignatureValidity::CryptographicallyValid => "valid",
            SignatureValidity::CryptographicallyInvalid => "invalid",
            SignatureValidity::UnknownSigner => "unknown-signer",
            SignatureValidity::MalformedSignature => "malformed",
            SignatureValidity::UnsupportedAlgorithm => "unsupported",
        };
        let text = json!({
            "validity": validity,
            "signer_fingerprint": v.signer_fingerprint.map(|f| f.to_hex()),
            "signer_primary_fingerprint": v.signer_primary_fingerprint.map(|f| f.to_hex()),
            "signer_key_id": v.signer_key_id.map(|k| k.to_hex()),
            "weak_algorithm": v.weak_algorithm,
        })
        .to_string();
        unsafe { write_buf(text.as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_decrypt_with_details_v1(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
    details: *mut *mut u8,
    details_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() || details.is_null() || details_len.is_null() {
        return 1;
    }
    *out = ptr::null_mut();
    *out_len = 0;
    *details = ptr::null_mut();
    *details_len = 0;
    run(|| {
        clear_error();
        let pass = String::from_utf8_lossy(read_slice(passphrase, passphrase_len));
        let result = scomm_openpgp_sequoia::decrypt(
            read_slice(ciphertext, ciphertext_len),
            read_slice(private_key, private_key_len),
            Some(pass.as_ref()),
            &[],
        )?;
        let mut evidence = json!({});
        if let Some(id) = result.cipher {
            evidence["contentCipher"] = algorithm("observed", "openpgp.symmetric", id);
        }
        if let Some(id) = result.aead {
            evidence["aeadMode"] = algorithm("observed", "openpgp.aead", id);
            evidence["integrity"] = json!({"state":"verified","value":"aead_passed"});
        }
        if let Some(id) = result.recipient_algorithm {
            evidence["recipientAlgorithm"] = algorithm("observed", "openpgp.public_key", id);
        }
        if let Some(id) = result.recipient_key_id {
            evidence["localRecipientKeyId"] = json!({"state":"observed","value":id.to_hex()});
        }
        let details_text = json!({
            "version":1, "protocol":"openpgp", "source":"native_operation",
            "operation":"decrypt", "state":"succeeded", "evidence":evidence,
        })
        .to_string();
        write_buf(&result.plaintext, out, out_len);
        write_buf(details_text.as_bytes(), details, details_len);
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_verify_detached_with_details_v1(
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    verdict: *mut *mut u8,
    verdict_len: *mut usize,
    details: *mut *mut u8,
    details_len: *mut usize,
) -> i32 {
    if verdict.is_null() || verdict_len.is_null() || details.is_null() || details_len.is_null() {
        return 1;
    }
    *verdict = ptr::null_mut();
    *verdict_len = 0;
    *details = ptr::null_mut();
    *details_len = 0;
    run(|| {
        clear_error();
        let (result, algorithms) = scomm_openpgp_sequoia::verify_detached_with_details(
            read_slice(data, data_len),
            read_slice(signature, signature_len),
            read_slice(public_key, public_key_len),
        )?;
        let (validity, state) = match result.validity {
            SignatureValidity::CryptographicallyValid => ("valid", "succeeded"),
            SignatureValidity::CryptographicallyInvalid => ("invalid", "failed"),
            SignatureValidity::UnknownSigner => ("unknown-signer", "incomplete"),
            SignatureValidity::MalformedSignature => ("malformed", "failed"),
            SignatureValidity::UnsupportedAlgorithm => ("unsupported", "unsupported"),
        };
        let mut evidence = json!({});
        if let Some((version, public_key, hash)) = algorithms {
            evidence["signatureValidity"] = json!({"state":"verified","value":"valid"});
            evidence["signatureVersion"] = json!({"state":"observed","value":version});
            evidence["signatureAlgorithm"] =
                algorithm("observed", "openpgp.public_key", public_key);
            evidence["digestAlgorithm"] = algorithm("observed", "openpgp.hash", hash);
        }
        if validity == "valid" {
            if let Some(fp) = result.signer_fingerprint.as_ref() {
                evidence["signerFingerprint"] = json!({"state":"verified","value":fp.to_hex()});
            }
        }
        let verdict_text = json!({
            "validity":validity,
            "signer_fingerprint":result.signer_fingerprint.map(|f| f.to_hex()),
            "signer_primary_fingerprint":result.signer_primary_fingerprint.map(|f| f.to_hex()),
            "signer_key_id":result.signer_key_id.map(|k| k.to_hex()),
            "weak_algorithm":result.weak_algorithm,
        })
        .to_string();
        let details_text = json!({
            "version":1, "protocol":"openpgp", "source":"native_operation",
            "operation":"verify_detached", "state":state, "evidence":evidence,
        })
        .to_string();
        write_buf(verdict_text.as_bytes(), verdict, verdict_len);
        write_buf(details_text.as_bytes(), details, details_len);
        Ok(0)
    })
}

fn algorithm(state: &str, namespace: &str, id: u8) -> Value {
    json!({"state":state,"value":{"namespace":namespace,"id":id}})
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_inspect_public_envelope_v1(
    envelope: *const u8,
    envelope_len: usize,
    input_kind: u32,
    input_extent: u32,
    details: *mut *mut u8,
    details_len: *mut usize,
) -> i32 {
    use scomm_openpgp_sequoia::{inspect_public_envelope, PublicPacket};
    if details.is_null() || details_len.is_null() {
        return 1;
    }
    *details = ptr::null_mut();
    *details_len = 0;
    if envelope.is_null()
        || envelope_len == 0
        || !matches!(input_kind, 1 | 2)
        || !matches!(input_extent, 1 | 2)
    {
        return 1;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let mut evidence = json!({});
        let (state, limit) = if input_extent == 2 {
            ("unavailable", Some("unsupported_input_extent"))
        } else if envelope_len > 256 * 1024 {
            ("unavailable", Some("input_bytes"))
        } else {
            match inspect_public_envelope(read_slice(envelope, envelope_len), input_kind == 2) {
                Ok(result) => {
                    if let Some(format) = result.format {
                        evidence["format"] = json!({"state":"declared","value":format});
                    }
                    if let Some(id) = result.cipher {
                        evidence["contentCipher"] = algorithm("declared", "openpgp.symmetric", id);
                    }
                    if let Some(id) = result.aead {
                        evidence["aeadMode"] = algorithm("declared", "openpgp.aead", id);
                    }
                    let entries: Vec<_> = result
                        .packets
                        .into_iter()
                        .map(|p| match p {
                            PublicPacket::Recipient {
                                version,
                                algorithm: id,
                            } => json!({
                                "version":{"state":"declared","value":version},
                                "algorithm":algorithm("declared", "openpgp.public_key", id),
                            }),
                            PublicPacket::Signature {
                                version,
                                algorithm: id,
                                hash,
                            } => json!({
                                "version":{"state":"declared","value":version},
                                "algorithm":algorithm("declared", "openpgp.public_key", id),
                                "digest":algorithm("declared", "openpgp.hash", hash),
                            }),
                        })
                        .collect();
                    let key = if input_kind == 2 {
                        "signers"
                    } else {
                        "recipients"
                    };
                    evidence[key] = json!({"complete":result.limit.is_none(),"entries":entries});
                    (
                        if result.limit.is_none() {
                            "complete"
                        } else {
                            "partial"
                        },
                        result.limit,
                    )
                }
                Err(_) => ("malformed", None),
            }
        };
        let mut report = json!({
            "version":1,"protocol":"openpgp","source":"public_inspection",
            "operation":"inspect_public_envelope","state":state,"evidence":evidence,
        });
        if let Some(limit) = limit {
            report["limit"] = json!(limit);
        }
        let text = report.to_string();
        if text.len() > 16 * 1024 {
            return 2;
        }
        write_buf(text.as_bytes(), details, details_len);
        0
    })) {
        Ok(status) => status,
        Err(_) => 2,
    }
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

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_export_curve_secret(
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    signing: i32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        let secret = engine().export_curve_secret(&private_key, pass.as_deref(), signing != 0)?;
        unsafe { write_buf(&secret, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_openpgp_sign_pop(
    data: *const u8,
    data_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    notation: *const u8,
    notation_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let notation = String::from_utf8_lossy(read_slice(notation, notation_len)).into_owned();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        let sig = engine().sign_pop(&data, &private_key, pass.as_deref(), &notation)?;
        unsafe { write_buf(&sig, out, out_len) };
        Ok(0)
    })
}

fn prim_out(
    result: std::result::Result<Vec<u8>, String>,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    match result {
        Ok(bytes) => {
            clear_error();
            unsafe { write_buf(&bytes, out, out_len) };
            0
        }
        Err(err) => {
            set_error(err);
            -1
        }
    }
}

/// Opaque streaming SHA-256 context (R11); null on failure. Free it with
/// [scomm_prims_sha256_free].
#[no_mangle]
pub extern "C" fn scomm_prims_sha256_new() -> *mut prims::Sha256Stream {
    match prims::Sha256Stream::new() {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(e) => {
            set_error(e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_sha256_update(
    ctx: *mut prims::Sha256Stream,
    data: *const u8,
    data_len: usize,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        set_error("sha256 context".into());
        return -1;
    };
    match ctx.update(read_slice(data, data_len)) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Writes the 32-byte digest to `out` and resets the context.
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_sha256_final(
    ctx: *mut prims::Sha256Stream,
    out: *mut u8,
) -> i32 {
    let Some(ctx) = ctx.as_mut() else {
        set_error("sha256 context".into());
        return -1;
    };
    if out.is_null() {
        set_error("sha256 output".into());
        return -1;
    }
    match ctx.finish() {
        Ok(d) => {
            ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
            0
        }
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Frees a context from [scomm_prims_sha256_new]; null is ignored.
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_sha256_free(ctx: *mut prims::Sha256Stream) {
    if !ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_sha256(
    data: *const u8,
    data_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len);
    prim_out(prims::sha256(data), out, out_len)
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_sha512(
    data: *const u8,
    data_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(prims::sha512(read_slice(data, data_len)), out, out_len)
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_hmac_sha256(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::hmac_sha256(read_slice(key, key_len), read_slice(data, data_len)),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_aes256gcm_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ct_out: *mut *mut u8,
    ct_len: *mut usize,
    tag_out: *mut *mut u8,
    tag_len: *mut usize,
) -> i32 {
    match prims::aes256gcm_encrypt(
        read_slice(key, key_len),
        read_slice(nonce, nonce_len),
        read_slice(aad, aad_len),
        read_slice(plaintext, plaintext_len),
    ) {
        Ok((ct, tag)) => {
            clear_error();
            write_buf(&ct, ct_out, ct_len);
            write_buf(&tag, tag_out, tag_len);
            0
        }
        Err(err) => {
            set_error(err);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_aes256gcm_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    tag_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::aes256gcm_decrypt(
            read_slice(key, key_len),
            read_slice(nonce, nonce_len),
            read_slice(aad, aad_len),
            read_slice(ciphertext, ciphertext_len),
            read_slice(tag, tag_len),
        ),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_pbkdf2_hmac_sha256(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: usize,
    out_len: usize,
    out: *mut *mut u8,
    out_out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::pbkdf2_hmac_sha256(
            read_slice(password, password_len),
            read_slice(salt, salt_len),
            iterations,
            out_len,
        ),
        out,
        out_out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_argon2id(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    lanes: u32,
    mem_kib: u32,
    out_len: usize,
    out: *mut *mut u8,
    out_out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::argon2id_derive(
            read_slice(password, password_len),
            read_slice(salt, salt_len),
            iterations,
            lanes,
            mem_kib,
            out_len,
        ),
        out,
        out_out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_random(
    n: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(prims::random(n), out, out_len)
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_ed25519_sign(
    seed: *const u8,
    seed_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::ed25519_sign(read_slice(seed, seed_len), read_slice(message, message_len)),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_ed25519_public(
    seed: *const u8,
    seed_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::ed25519_from_seed(read_slice(seed, seed_len)).map(|(public, _)| public),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_ed25519_verify(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    match prims::ed25519_verify(
        read_slice(public_key, public_key_len),
        read_slice(message, message_len),
        read_slice(signature, signature_len),
    ) {
        Ok(true) => {
            clear_error();
            1
        }
        Ok(false) => {
            clear_error();
            0
        }
        Err(err) => {
            set_error(err);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_x25519_public(
    seed: *const u8,
    seed_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::x25519_public(read_slice(seed, seed_len)),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_x25519_dh(
    seed: *const u8,
    seed_len: usize,
    peer: *const u8,
    peer_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::x25519_dh(read_slice(seed, seed_len), read_slice(peer, peer_len)),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_mldsa65_sign(
    seed: *const u8,
    seed_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::mldsa65_sign(read_slice(seed, seed_len), read_slice(message, message_len)),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_msk_sign(
    seed: *const u8,
    seed_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::msk_sign(read_slice(seed, seed_len), read_slice(message, message_len)),
        out,
        out_len,
    )
}

fn prim_bool(result: std::result::Result<bool, String>) -> i32 {
    match result {
        Ok(v) => {
            clear_error();
            v as i32
        }
        Err(err) => {
            set_error(err);
            -1
        }
    }
}

/// `alg`: 1 MD5, 2 SHA-1, 3 SHA-256, 4 SHA-384, 5 SHA-512.
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_digest(
    alg: i32,
    data: *const u8,
    data_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(prims::digest(alg, read_slice(data, data_len)), out, out_len)
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_hmac(
    alg: i32,
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::hmac(alg, read_slice(key, key_len), read_slice(data, data_len)),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_pbkdf2(
    alg: i32,
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: usize,
    key_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::pbkdf2(
            alg,
            read_slice(password, password_len),
            read_slice(salt, salt_len),
            iterations,
            key_len,
        ),
        out,
        out_len,
    )
}

/// RSASSA-PKCS1-v1_5 over a PKCS#8 (or PKCS#1) DER private key.
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_rsa_pkcs1_sign(
    alg: i32,
    private_key_der: *const u8,
    private_key_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::rsa_pkcs1_sign(
            alg,
            read_slice(private_key_der, private_key_len),
            read_slice(message, message_len),
        ),
        out,
        out_len,
    )
}

/// Returns 1 valid, 0 invalid signature, -1 error (bad key or algorithm).
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_rsa_pkcs1_verify(
    alg: i32,
    spki_der: *const u8,
    spki_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    prim_bool(prims::rsa_pkcs1_verify(
        alg,
        read_slice(spki_der, spki_len),
        read_slice(message, message_len),
        read_slice(signature, signature_len),
    ))
}

/// ECDSA verify. `raw` != 0 means a JWS `r || s` signature, else ASN.1 DER.
/// Returns 1 valid, 0 invalid signature, -1 error.
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_ecdsa_verify(
    alg: i32,
    spki_der: *const u8,
    spki_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
    raw: i32,
) -> i32 {
    prim_bool(prims::ecdsa_verify(
        alg,
        read_slice(spki_der, spki_len),
        read_slice(message, message_len),
        read_slice(signature, signature_len),
        raw != 0,
    ))
}

/// AES-CBC with PKCS#7 padding; the key length (16, 24, 32) selects the cipher.
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_aes_cbc_encrypt(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::aes_cbc_encrypt(
            read_slice(key, key_len),
            read_slice(iv, iv_len),
            read_slice(plaintext, plaintext_len),
        ),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_aes_cbc_decrypt(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::aes_cbc_decrypt(
            read_slice(key, key_len),
            read_slice(iv, iv_len),
            read_slice(ciphertext, ciphertext_len),
        ),
        out,
        out_len,
    )
}

unsafe fn write_pair(
    pair: std::result::Result<(Vec<u8>, Vec<u8>), String>,
    a_out: *mut *mut u8,
    a_len: *mut usize,
    b_out: *mut *mut u8,
    b_len: *mut usize,
) -> i32 {
    match pair {
        Ok((a, b)) => {
            clear_error();
            write_buf(&a, a_out, a_len);
            write_buf(&b, b_out, b_len);
            0
        }
        Err(err) => {
            set_error(err);
            -1
        }
    }
}

/// `kind`: 1 EC P-256, 2 RSA-2048, 3 RSA-3072, 4 Ed25519. Outputs a PKCS#8
/// PrivateKeyInfo DER and a SubjectPublicKeyInfo DER.
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_pkey_generate(
    kind: i32,
    pkcs8_out: *mut *mut u8,
    pkcs8_len: *mut usize,
    spki_out: *mut *mut u8,
    spki_len: *mut usize,
) -> i32 {
    write_pair(
        prims::pkey_generate(kind),
        pkcs8_out,
        pkcs8_len,
        spki_out,
        spki_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_ec_p256_from_scalar(
    scalar: *const u8,
    scalar_len: usize,
    pkcs8_out: *mut *mut u8,
    pkcs8_len: *mut usize,
    spki_out: *mut *mut u8,
    spki_len: *mut usize,
) -> i32 {
    write_pair(
        prims::ec_p256_from_scalar(read_slice(scalar, scalar_len)),
        pkcs8_out,
        pkcs8_len,
        spki_out,
        spki_len,
    )
}

/// `scheme`: 1 ECDSA-SHA256 (DER), 2 RSASSA-PKCS1-v1_5-SHA256, 3 Ed25519.
#[no_mangle]
pub unsafe extern "C" fn scomm_prims_pkey_sign(
    scheme: i32,
    pkcs8: *const u8,
    pkcs8_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::pkey_sign(
            scheme,
            read_slice(pkcs8, pkcs8_len),
            read_slice(message, message_len),
        ),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_pkcs8_encrypt(
    pkcs8: *const u8,
    pkcs8_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    iterations: u32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::pkcs8_encrypt(
            read_slice(pkcs8, pkcs8_len),
            read_slice(passphrase, passphrase_len),
            iterations,
        ),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_pkcs8_decrypt(
    encrypted: *const u8,
    encrypted_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::pkcs8_decrypt(
            read_slice(encrypted, encrypted_len),
            read_slice(passphrase, passphrase_len),
        ),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_csr_create(
    pkcs8: *const u8,
    pkcs8_len: usize,
    subject: *const u8,
    subject_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let subject = String::from_utf8_lossy(read_slice(subject, subject_len)).into_owned();
    prim_out(
        prims::csr_create(read_slice(pkcs8, pkcs8_len), &subject),
        out,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn scomm_prims_pkcs8_public_spki(
    pkcs8: *const u8,
    pkcs8_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    prim_out(
        prims::pkcs8_public_spki(read_slice(pkcs8, pkcs8_len)),
        out,
        out_len,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspection_is_declared_and_refuses_prefix_and_oversized_inputs() {
        use super::*;
        fn inspect(bytes: &[u8], extent: u32) -> Value {
            let mut out = ptr::null_mut();
            let mut len = 0;
            unsafe {
                let code = scomm_openpgp_inspect_public_envelope_v1(
                    bytes.as_ptr(),
                    bytes.len(),
                    1,
                    extent,
                    &mut out,
                    &mut len,
                );
                assert_eq!(code, 0);
                assert!(len <= 16 * 1024);
                let decoded = serde_json::from_slice(read_slice(out, len)).unwrap();
                scomm_openpgp_buffer_free(out, len);
                decoded
            }
        }
        // SEIPD v2 declares a cipher and an AEAD mode. The dummy payload
        // cannot establish integrity, and the inspector never checks it.
        let mut bytes = vec![0xd2, 52, 2, 9, 2, 0];
        bytes.extend([0; 48]);
        let report = inspect(&bytes, 1);
        assert_eq!(report["source"], "public_inspection");
        assert_eq!(report["evidence"]["contentCipher"]["state"], "declared");
        assert_eq!(report["evidence"]["contentCipher"]["value"]["id"], 9);
        assert!(report["evidence"].get("integrity").is_none());
        assert_eq!(inspect(&bytes, 2)["limit"], "unsupported_input_extent");
        assert_eq!(inspect(&vec![0; 256 * 1024 + 1], 1)["limit"], "input_bytes");
    }

    #[test]
    fn details_preserve_decrypt_and_verify_results() {
        use super::*;
        let pgp = engine();
        let key = pgp
            .generate_key(&GenerateKeyOptions {
                userid: "Test <test@example.com>".into(),
                passphrase: None,
                // v6: mail to a v4 key is SEIPDv1 (Thunderbird interop).
                profile: KeyProfile::Rfc9580Cv25519,
                ..Default::default()
            })
            .unwrap();
        let data = b"message security details fixture";
        let ciphertext = pgp
            .encrypt(data, &[&key.public], &EncryptOptions { armored: false })
            .unwrap();
        let signature = pgp
            .sign(
                data,
                &key.secret,
                None,
                &SignOptions {
                    armored: false,
                    detached: true,
                },
            )
            .unwrap();
        let inspect = scomm_openpgp_sequoia::inspect_public_envelope(&ciphertext, false).unwrap();
        assert_eq!(inspect.format, Some("seipd_v2"));
        assert_eq!(inspect.packets.len(), 1);

        unsafe {
            let (mut out, mut len) = (ptr::null_mut(), 0);
            let (mut details, mut details_len) = (ptr::null_mut(), 0);
            assert_eq!(
                scomm_openpgp_decrypt_with_details_v1(
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                    key.secret.as_ptr(),
                    key.secret.len(),
                    ptr::null(),
                    0,
                    &mut out,
                    &mut len,
                    &mut details,
                    &mut details_len,
                ),
                0
            );
            assert_eq!(read_slice(out, len), data);
            let evidence: Value = serde_json::from_slice(read_slice(details, details_len)).unwrap();
            assert_eq!(evidence["evidence"]["integrity"]["value"], "aead_passed");
            assert_eq!(evidence["evidence"]["integrity"]["state"], "verified");
            scomm_openpgp_buffer_free(out, len);
            scomm_openpgp_buffer_free(details, details_len);

            assert_eq!(
                scomm_openpgp_verify_detached_with_details_v1(
                    data.as_ptr(),
                    data.len(),
                    signature.bytes.as_ptr(),
                    signature.bytes.len(),
                    key.public.as_ptr(),
                    key.public.len(),
                    &mut out,
                    &mut len,
                    &mut details,
                    &mut details_len,
                ),
                0
            );
            let verdict: Value = serde_json::from_slice(read_slice(out, len)).unwrap();
            let evidence: Value = serde_json::from_slice(read_slice(details, details_len)).unwrap();
            assert_eq!(verdict["validity"], "valid");
            assert_eq!(
                evidence["evidence"]["signatureValidity"]["state"],
                "verified"
            );
            assert!(evidence["evidence"]["digestAlgorithm"]["value"]["id"].is_number());
            scomm_openpgp_buffer_free(out, len);
            scomm_openpgp_buffer_free(details, details_len);
        }
    }

    #[test]
    fn links_openssl_4_1() {
        let version = crate::prims::openssl_version();
        assert!(version.starts_with("OpenSSL 4.1."), "{version}");
    }

    /// The C ABI of the streaming digest: chunks, reuse after final, and
    /// refusal of a null context or output.
    #[test]
    fn sha256_stream_c_abi() {
        use super::*;
        unsafe {
            let ctx = scomm_prims_sha256_new();
            assert!(!ctx.is_null());
            for chunk in [&b"a"[..], b"", b"bc"] {
                assert_eq!(
                    scomm_prims_sha256_update(ctx, chunk.as_ptr(), chunk.len()),
                    0
                );
            }
            let mut out = [0u8; 32];
            assert_eq!(scomm_prims_sha256_final(ctx, out.as_mut_ptr()), 0);
            assert_eq!(out.to_vec(), crate::prims::sha256(b"abc").unwrap());
            assert_eq!(scomm_prims_sha256_update(ctx, ptr::null(), 0), 0);
            assert_eq!(scomm_prims_sha256_final(ctx, out.as_mut_ptr()), 0);
            assert_eq!(out.to_vec(), crate::prims::sha256(b"").unwrap());
            assert_eq!(scomm_prims_sha256_final(ctx, ptr::null_mut()), -1);
            scomm_prims_sha256_free(ctx);
            assert_eq!(
                scomm_prims_sha256_update(ptr::null_mut(), b"x".as_ptr(), 1),
                -1
            );
            assert_eq!(
                scomm_prims_sha256_final(ptr::null_mut(), out.as_mut_ptr()),
                -1
            );
            scomm_prims_sha256_free(ptr::null_mut());
        }
    }
}
