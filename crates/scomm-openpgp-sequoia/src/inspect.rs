use std::time::{SystemTime, UNIX_EPOCH};

use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::RevocationStatus;
use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::Packet;
use scomm_openpgp_core::*;

use crate::{catalog_name, fingerprint_of, key_id_from_handle, key_id_of};

pub fn key_info(cert: &Cert, p: &StandardPolicy<'_>) -> Result<OpenPgpKeyInfo> {
    let primary = cert.primary_key();
    let created = unix(primary.key().creation_time());
    let mut expires = None;
    let mut revoked = false;
    if let Ok(vc) = cert.with_policy(p, None) {
        revoked = matches!(vc.revocation_status(), RevocationStatus::Revoked(_));
        expires = vc.primary_key().key_expiration_time().and_then(unix);
    }

    let mut identities = Vec::new();
    for ua in cert.userids() {
        let uid = ua.userid();
        identities.push(OpenPgpIdentity {
            name: uid.name().ok().flatten().map(|s| s.to_string()),
            email: uid.email().ok().flatten().map(|s| s.to_string()),
        });
    }

    let mut capabilities = Vec::new();
    if let Ok(vc) = cert.with_policy(p, None) {
        for ka in vc.keys() {
            let flags = ka.key_flags().unwrap_or_else(sequoia_openpgp::types::KeyFlags::empty);
            if flags.for_certification() {
                push_unique(&mut capabilities, OpenPgpKeyUsage::Certification);
            }
            if flags.for_signing() {
                push_unique(&mut capabilities, OpenPgpKeyUsage::Signing);
            }
            if flags.for_transport_encryption() || flags.for_storage_encryption() {
                push_unique(&mut capabilities, OpenPgpKeyUsage::Encryption);
            }
            if flags.for_authentication() {
                push_unique(&mut capabilities, OpenPgpKeyUsage::Authentication);
            }
        }
    }

    let mut subkeys = Vec::new();
    let primary_fp = cert.fingerprint();
    if let Ok(vc) = cert.with_policy(p, None) {
        for ka in vc.keys() {
            if ka.key().fingerprint() == primary_fp {
                continue;
            }
            let flags = ka.key_flags().unwrap_or_else(sequoia_openpgp::types::KeyFlags::empty);
            let mut caps = Vec::new();
            if flags.for_certification() {
                caps.push(OpenPgpKeyUsage::Certification);
            }
            if flags.for_signing() {
                caps.push(OpenPgpKeyUsage::Signing);
            }
            if flags.for_transport_encryption() || flags.for_storage_encryption() {
                caps.push(OpenPgpKeyUsage::Encryption);
            }
            if flags.for_authentication() {
                caps.push(OpenPgpKeyUsage::Authentication);
            }
            subkeys.push(OpenPgpSubkeyInfo {
                fingerprint: fingerprint_of(ka.key().fingerprint()),
                key_id: key_id_of(&ka.key().keyid()),
                algorithm: catalog_name(ka.key().pk_algo()),
                capabilities: caps,
            });
        }
    }

    let secret_encrypted = cert
        .keys()
        .secret()
        .any(|ka| !ka.key().has_unencrypted_secret());

    Ok(OpenPgpKeyInfo {
        fingerprint: fingerprint_of(cert.fingerprint()),
        key_id: key_id_of(&cert.keyid()),
        identities,
        algorithm: catalog_name(primary.key().pk_algo()),
        created_at: created,
        expires_at: expires,
        revoked,
        capabilities,
        has_secret: cert.is_tsk(),
        secret_encrypted,
        subkeys,
    })
}

fn push_unique(caps: &mut Vec<OpenPgpKeyUsage>, u: OpenPgpKeyUsage) {
    if !caps.contains(&u) {
        caps.push(u);
    }
}

fn unix(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
}

pub fn message(data: &[u8]) -> Result<MessageInfo> {
    let armored = data.windows(11).any(|w| w == b"-----BEGIN ");
    let bytes: Vec<u8> = if armored {
        crate::SequoiaOpenPgp
            .dearmor(data)
            .unwrap_or_else(|_| data.to_vec())
    } else {
        data.to_vec()
    };

    let mut info = MessageInfo {
        armored,
        ..MessageInfo::default()
    };

    let mut ppr = PacketParser::from_bytes(&bytes)
        .map_err(|_| OpenPgpError::MalformedMessage)?;
    while let PacketParserResult::Some(pp) = ppr {
        match pp.packet {
            Packet::PKESK(ref pkesk) => {
                info.encrypted = true;
                if let Some(h) = pkesk.recipient() {
                    info.recipient_key_ids.push(key_id_from_handle(&h));
                }
            }
            Packet::SKESK(_) | Packet::SEIP(_) => {
                info.encrypted = true;
            }
            Packet::OnePassSig(ref ops) => {
                info.signed = true;
                info.signature_key_ids
                    .push(key_id_from_handle(&KeyHandle::from(ops.issuer())));
            }
            Packet::Signature(ref sig) => {
                info.signed = true;
                for issuer in sig.get_issuers() {
                    info.signature_key_ids.push(key_id_from_handle(&issuer));
                }
            }
            Packet::Literal(_) => {}
            _ => {}
        }
        ppr = pp
            .recurse()
            .map_err(|_| OpenPgpError::MalformedMessage)?
            .1;
    }
    Ok(info)
}
