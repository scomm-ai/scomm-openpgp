# Architecture

Scomm.AI owns policy, vault/CKVF, pubkey discovery, MIME, and UI.

`scomm-openpgp` owns OpenPGP packet crypto only.

| Crate | Sequoia? | Role |
|---|---|---|
| `scomm-openpgp-core` | No | Types, `OpenPgpProvider`, error codes, `ABI_VERSION` |
| `scomm-openpgp-sequoia` | Yes | Only crate allowed to `use sequoia_openpgp` |

Rules:

- Bytes in / bytes out. No filesystem, SQLite, or HTTP.
- Verification is cryptographic validity, not trust.
- Generate/sign/encrypt: `StandardPolicy::new()`.
- Decrypt: `StandardPolicy::at(UNIX_EPOCH)` (decrypt-historical). Do not tighten that in the same bump as Sequoia.
- Default generate profile: classical Cv25519. RFC 9980 PQC generate is a later, flagged addition.
- Dual-engine in Scomm.AI was dropped: the app uses this FFI only (greenfield).
- FFI/Dart sits on `OpenPgpProvider` without exposing Sequoia types.
