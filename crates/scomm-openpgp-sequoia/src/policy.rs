use sequoia_openpgp::policy::StandardPolicy;
use std::time::UNIX_EPOCH;

/// Strict policy for generate / sign / encrypt (current Sequoia defaults).
pub fn generate_policy() -> StandardPolicy<'static> {
    StandardPolicy::new()
}

/// Inbox decrypt: evaluate policy as of the epoch so historical ciphers
/// (e.g. 3DES) that `StandardPolicy::new()` rejects after 2017 still open.
/// Do not use this for generate/sign.
pub fn decrypt_policy() -> StandardPolicy<'static> {
    StandardPolicy::at(UNIX_EPOCH)
}
