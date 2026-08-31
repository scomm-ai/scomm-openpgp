# scomm-openpgp

Reusable OpenPGP SDK for Scomm.AI. Sequoia PGP is an **implementation detail**.

## What this is

OpenPGP key generate/inspect, armor, sign/verify, encrypt/decrypt (including encrypt+sign and decrypt+verify) behind Scomm-owned types.

## What this is not

Not a key vault, CKVF, pubkey.scomm.ai, S/MIME, or an email client. Callers pass key **bytes**. There is no network access.

## Architecture

```
Scomm.AI (policy, vault, MIME, discovery)
   → Dart `scomm_openpgp` (`dart/scomm_openpgp`)
   → C ABI (`scomm-openpgp-ffi` cdylib)
   → `scomm-openpgp-core`
   → `scomm-openpgp-sequoia`
   → sequoia-openpgp 2.4.1
```

## Status (0.1.0)

- Rust workspace: `scomm-openpgp-core`, `scomm-openpgp-sequoia`, `scomm-openpgp-ffi`
- Dart FFI plugin: `dart/scomm_openpgp` (Windows / Linux / macOS)
- Classical Ed25519 + X25519 generate; encrypt to multiple recipients; detached sign/verify
- Decrypt uses a **historical** Sequoia policy (epoch `StandardPolicy::at`) so old inbox ciphers are not cut off by generate-time defaults
- LibrePGP Kyber (algorithm IDs 105/106) is rejected
- Default crypto feature: **RustCrypto** (dev when OpenSSL 3.5 is missing). Production target remains **OpenSSL ≥ 3.5** (`--features openssl --no-default-features`) so RFC 9980 and later CMS share primitives

Scomm.AI should depend on this repo by **git URL** (`path: dart/scomm_openpgp`), not a local path.

## Build / test

```bash
cargo test
```

OpenSSL backend (requires `OPENSSL_DIR` on MSVC):

```bash
cargo test -p scomm-openpgp-sequoia --no-default-features --features openssl
```

## License

This repository: LGPL-2.0-or-later (see `LICENSE`).

`sequoia-openpgp` 2.4.1: LGPL-2.0-or-later — exact text in `THIRD_PARTY_LICENSES/sequoia-openpgp-2.4.1-LICENSE.txt`.
