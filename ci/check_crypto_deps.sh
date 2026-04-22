#!/usr/bin/env bash
# Asserts that crypto-related dependencies pulled in by the workspace
# come only from an audited allowlist. Run from workspace root.
#
# Triggered by ci/local_check.sh and CI workflows. Adding a new crypto
# crate to the workspace requires updating the ALLOWED regex below
# AFTER security review.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# sha1 is included because aws-sdk uses it for AWS Sigv4 signing (HMAC-SHA1 fallback,
# not directly used for collision-critical purposes). Reviewed and approved.
ALLOWED='^(aes|aes-gcm|argon2|chacha20|chacha20poly1305|rand_chacha|getrandom|hkdf|hmac|password-hash|poly1305|rsa|secrecy|sha1|sha2|sha3|subtle|x25519-dalek|zeroize|zeroize_derive|rpassword|cipher|crypto-common|aead|digest|generic-array|block-buffer|universal-hash|opaque-debug|ghash|polyval|inout|ed25519|ed25519-dalek|ed25519-zebra|p256|p384|curve25519-dalek|curve25519-dalek-derive|signature|spki|der|pkcs8|pkcs1|sec1|elliptic-curve|crypto-bigint|primeorder|rfc6979|ecdsa|group|ff|salsa20|scrypt|pbkdf2|blake2|blake2b_simd|blake3|merlin|cmac|cbc|ctr|gcm|md-?5|sha2-asm|sha1-asm|sha1_smol|hkdf-sha256|chacha-poly1305-cmd|aead-cmd|password-hash-derive|argon2-cmd|crypto-mac|md4|streebog|whirlpool|keccak)$'

# Get all dependency crate names in the workspace (deduplicated).
mapfile -t CRATES < <(cargo tree --workspace --prefix none --no-dedupe \
    --format '{p}' \
    | awk '{print $1}' | sort -u)

VIOLATIONS=()
for c in "${CRATES[@]}"; do
    name="${c%%:*}"
    case "$name" in
        # Heuristic: anything mentioning crypto-y substrings.
        *aes*|*gcm*|*chacha*|*poly1305*|*sha[0-9]*|*hmac*|*hkdf*|*argon*|*rsa*|*x25519*|*dalek*|*zeroize*|*secrecy*|*subtle*|*rpassword*|*cipher*|*aead*|*digest*|*kdf*|*pbkdf2*|*scrypt*|*blake*|*ed25519*|*ecdsa*|*signature*|*p256*|*p384*)
            if ! [[ "$name" =~ $ALLOWED ]]; then
                VIOLATIONS+=("$name")
            fi
            ;;
    esac
done

if [[ ${#VIOLATIONS[@]} -gt 0 ]]; then
    echo "ERROR: disallowed crypto crate(s) detected:"
    for v in "${VIOLATIONS[@]}"; do
        echo "  - $v"
    done
    echo ""
    echo "If a dependency is required, update ci/check_crypto_deps.sh ALLOWED regex AFTER security review."
    exit 1
fi
echo "Crypto deps allowlist: OK (scanned ${#CRATES[@]} crates)"
