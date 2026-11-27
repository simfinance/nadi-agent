#!/usr/bin/env bash
set -euo pipefail

expected_fingerprint="91d063a323ffb7feaad3e4bf39d750ec339b2206b74f762d11e1f291267a49e1"

if [ "$#" -ne 3 ]; then
    printf 'Usage: %s <trusted-ed25519-public-key.pem> <package-deb> <detached-signature>\n' "$0" >&2
    exit 2
fi

public_key="$1"
package_path="$2"
signature_path="$3"

for path in "$public_key" "$package_path" "$signature_path"; do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        printf 'Signature verification inputs must be regular non-symlink files.\n' >&2
        exit 1
    fi
done

actual_fingerprint="$(openssl pkey -pubin -in "$public_key" -outform DER | sha256sum | awk '{print $1}')"

if [ "$actual_fingerprint" != "$expected_fingerprint" ]; then
    printf 'Release public key fingerprint does not match the pinned NADI trust anchor.\n' >&2
    exit 1
fi

openssl pkeyutl \
    -verify \
    -pubin \
    -inkey "$public_key" \
    -rawin \
    -in "$package_path" \
    -sigfile "$signature_path" \
    >/dev/null
