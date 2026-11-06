#!/usr/bin/env bash
# Regenerates the GnuPG corpus that tests/interop_gnupg.rs reads.
#
# Everything here is throwaway test material: the secret keys have no passphrase
# and are public in this repo. Nothing here protects anything.
#
# GnuPG refuses socket paths over about 100 characters. If gpg-agent fails to
# start, set SCOMM_INTEROP_GNUPGHOME to a short empty directory.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/crates/scomm-openpgp-sequoia/tests/fixtures/gnupg"
HOME_DIR="${SCOMM_INTEROP_GNUPGHOME:-$(mktemp -d /tmp/scg.XXXXXX)}"
mkdir -p "$HOME_DIR" "$OUT"
chmod 700 "$HOME_DIR"
trap 'gpgconf --homedir "$HOME_DIR" --kill all >/dev/null 2>&1 || true' EXIT

BASE=(--homedir "$HOME_DIR" --batch --yes --pinentry-mode loopback --passphrase '' --trust-model always)
g() { gpg "${BASE[@]}" "$@" 2>/dev/null; }

cd "$OUT"
rm -f ./*.pub ./*.sec ./*.pgp ./*.sig ./*.asc
printf 'Content-Type: text/plain\r\n\r\ninterop plaintext\r\n' > plaintext.bin
gpg --version | head -1 > generated-with.txt

add_key() { # name, sign algorithm, encrypt algorithm, extra flags
  local name=$1 sign=$2 encr=$3 uid="$1 <$1@example.com>"
  local extra=("${@:4}")
  g "${extra[@]}" --quick-gen-key "$uid" "$sign" sign never
  local fpr
  fpr=$(gpg "${BASE[@]}" --with-colons --list-keys "$uid" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
  g "${extra[@]}" --quick-add-key "$fpr" "$encr" encr never
  g --export --output "$name.pub" "$uid"
  g --export-secret-keys --output "$name.sec" "$uid"
}

add_key ed25519 ed25519 cv25519
add_key nistp256 nistp256 nistp256
add_key nistp384 nistp384 nistp384
add_key nistp521 nistp521 nistp521
add_key brainpoolP256r1 brainpoolP256r1 brainpoolP256r1
add_key brainpoolP384r1 brainpoolP384r1 brainpoolP384r1
add_key rsa3072 rsa3072 rsa3072

for name in ed25519 nistp256 nistp384 nistp521 brainpoolP256r1 brainpoolP384r1 rsa3072; do
  g -r "$name@example.com" --output "$name.default.pgp" --encrypt plaintext.bin
  g -u "$name@example.com" --output "$name.sig" --detach-sign plaintext.bin
done

r=(-r nistp256@example.com)
g "${r[@]}" --rfc4880 --output nistp256.rfc4880.pgp --encrypt plaintext.bin
g "${r[@]}" --compress-algo zip --output nistp256.zip.pgp --encrypt plaintext.bin
g "${r[@]}" --compress-algo zlib --output nistp256.zlib.pgp --encrypt plaintext.bin
g "${r[@]}" --compress-algo bzip2 --output nistp256.bzip2.pgp --encrypt plaintext.bin
g "${r[@]}" --compress-algo none --output nistp256.uncompressed.pgp --encrypt plaintext.bin
g "${r[@]}" --armor --output nistp256.armored.asc --encrypt plaintext.bin
g "${r[@]}" -u nistp256@example.com --output nistp256.signed.pgp --sign --encrypt plaintext.bin
g -u nistp256@example.com --armor --output nistp256.armored-sig.asc --detach-sign plaintext.bin
# LibrePGP OCB (packet tag 20). The key has to advertise it, so it needs its own
# key made with this compliance mode.
add_key ocb nistp256 nistp256 --compliance=gnupg
g --compliance=gnupg --compress-algo none -r ocb@example.com --output ocb.tag20.pgp --encrypt plaintext.bin

# GnuPG writes Ed448 keys as LibrePGP v5.
add_key ed448 ed448 cv448 --compliance=gnupg

ls -1 | wc -l
