//! ABI 6: key lifetime chosen at generation.

use std::time::{Duration, SystemTime};

use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;

const YEAR: u64 = 31_556_952;

fn gen(profile: KeyProfile, validity_years: Option<u32>) -> Result<GeneratedKey> {
    SequoiaOpenPgp::new().generate_key(&GenerateKeyOptions {
        userid: "Alice <alice@example.com>".into(),
        profile,
        validity_years,
        ..Default::default()
    })
}

/// Seconds from creation to expiry of the primary key and every subkey.
fn lifetimes(key: &GeneratedKey) -> Vec<u64> {
    let cert = Cert::from_bytes(&key.public).unwrap();
    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).unwrap();
    vc.keys()
        .map(|ka| {
            let expires = ka.key_expiration_time().expect("expires");
            expires.duration_since(ka.key().creation_time()).unwrap().as_secs()
        })
        .collect()
}

#[test]
fn every_key_expires_the_requested_years_after_creation() {
    for profile in [
        KeyProfile::ClassicalCv25519,
        KeyProfile::Rfc9580Cv25519,
        KeyProfile::Rfc9980MlDsa65,
    ] {
        for years in [1u32, 3, 10] {
            let key = gen(profile, Some(years)).unwrap();
            let all = lifetimes(&key);
            assert!(all.len() >= 2, "{profile:?}");
            for secs in all {
                assert_eq!(secs, u64::from(years) * YEAR, "{profile:?}");
            }
            let at = key.info.expires_at.expect("inspect expiry") as u64;
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
            let want = now + Duration::from_secs(u64::from(years) * YEAR);
            assert!(at.abs_diff(want.as_secs()) < 120, "{profile:?}");
        }
    }
}

#[test]
fn out_of_range_validity_is_refused() {
    for years in [0, MAX_VALIDITY_YEARS + 1] {
        assert!(matches!(
            gen(KeyProfile::ClassicalCv25519, Some(years)),
            Err(OpenPgpError::InvalidArgument(_))
        ));
    }
}
