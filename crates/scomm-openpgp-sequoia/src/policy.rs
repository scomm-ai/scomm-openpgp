use sequoia_openpgp::packet::Tag;
use sequoia_openpgp::policy::StandardPolicy;
use std::time::UNIX_EPOCH;

/// Strict policy for generate / sign / encrypt (current Sequoia defaults).
pub fn generate_policy() -> StandardPolicy<'static> {
    StandardPolicy::new()
}

/// Inbox decrypt: evaluate policy as of the epoch so historical ciphers
/// (e.g. 3DES) that `StandardPolicy::new()` rejects after 2017 still open.
/// Do not use this for generate/sign.
///
/// SED (Symmetrically Encrypted Data, no integrity protection) is refused
/// outright. Sequoia 2.4 cannot decrypt SED at all, but its policy would
/// accept it here: SED is rejected only for messages after 2004, which an
/// epoch-dated policy never reaches. This rule keeps unauthenticated,
/// malleable ciphertext (EFAIL) closed if a later Sequoia learns to read
/// it. GnuPG refuses it too.
pub fn decrypt_policy() -> StandardPolicy<'static> {
    let mut p = StandardPolicy::at(UNIX_EPOCH);
    p.reject_packet_tag(Tag::SED);
    p
}
