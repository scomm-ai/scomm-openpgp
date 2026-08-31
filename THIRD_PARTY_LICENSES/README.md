# Third-party licenses

Files here are copied from the **pinned** crate release, not paraphrased.

| File | Component | Version | SPDX |
|---|---|---|---|
| `sequoia-openpgp-2.4.1-LICENSE.txt` | sequoia-openpgp | 2.4.1 | LGPL-2.0-or-later |

Crypto backend (crate features):

- Default in this repo: Sequoia `crypto-rust` (dev/spike when OpenSSL 3.5 is not installed).
- Production intent: `crypto-openssl` with OpenSSL ≥ 3.5 on every shipped OS.

Ship the matching notices with the native library. Do not statically merge this into Scomm.AI in a way that requires distributing Scomm.AI source; prefer a replaceable shared library where the platform allows.
