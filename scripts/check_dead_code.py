"""Dead-code gates for libscomm_openpgp.

Fails if cargo tree pulls a banned RustCrypto crate other than the
sequoia-openpgp 2.4.1 S2K dependency on the rust `argon2` crate.
When libcrypto.lib or libcrypto.a is already built, also fails if a
removed cipher implementation symbol is present.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BANNED = (
    "ml-dsa",
    "ml-kem",
    "ed25519-dalek",
    "x25519-dalek",
    "rsa",
    "aes-gcm",
    "argon2",
    "sha2",
)
# sequoia-openpgp 2.4.1 uses this crate for OpenPGP Argon2 S2K.
# It is not optional in that release. Our own Argon2id is OpenSSL.
ALLOWED = {"argon2"}
IMPL_SYMBOLS = (
    b"CAST_ecb_encrypt",
    b"BF_ecb_encrypt",
    b"IDEA_ecb_encrypt",
    b"RIPEMD160_Init",
    b"RC2_set_key",
    b"RC4_set_key",
    b"MD4_Init",
    b"ossl_legacy_provider_init",
)


def cargo_tree() -> None:
    proc = subprocess.run(
        ["cargo", "tree", "-e", "all", "-p", "scomm-openpgp-ffi", "--prefix", "none"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    names = set()
    for line in proc.stdout.splitlines():
        name = line.split()[0] if line.split() else ""
        if name in BANNED:
            names.add(name)
    unexpected = names - ALLOWED
    if unexpected:
        raise SystemExit(f"banned crates in cargo tree: {sorted(unexpected)}")
    if "argon2" in names:
        print("note: rust argon2 remains via sequoia-openpgp S2K")


def symbol_scan() -> None:
    candidates = list(ROOT.glob("target/**/libcrypto.lib"))
    candidates += list(ROOT.glob("target/**/libcrypto.a"))
    if not candidates:
        print("note: no built libcrypto archive; symbol scan skipped")
        return
    lib = max(candidates, key=lambda path: path.stat().st_mtime)
    data = lib.read_bytes()
    found = [name.decode() for name in IMPL_SYMBOLS if name in data]
    if found:
        raise SystemExit(f"{lib} contains removed algorithms: {found}")
    version = data.find(b"OpenSSL 4.1.0-beta1")
    if version < 0:
        raise SystemExit(f"{lib} does not report OpenSSL 4.1.0-beta1")
    print(f"libcrypto scan ok: {lib}")


def main() -> None:
    cargo_tree()
    if "--tree-only" not in sys.argv:
        symbol_scan()


if __name__ == "__main__":
    main()
