#!/usr/bin/env bash
set -euo pipefail

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

openssl pkeyutl \
    -verify \
    -pubin \
    -inkey "$public_key" \
    -rawin \
    -in "$package_path" \
    -sigfile "$signature_path" \
    >/dev/null
