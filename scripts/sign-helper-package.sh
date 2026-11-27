#!/usr/bin/env bash
set -euo pipefail

expected_fingerprint="91d063a323ffb7feaad3e4bf39d750ec339b2206b74f762d11e1f291267a49e1"

if [ "$#" -ne 3 ]; then
    printf 'Usage: %s <release-private-key.pem> <package-deb> <output-signature>\n' "$0" >&2
    exit 2
fi

private_key="$1"
package_path="$2"
signature_path="$3"

for path in "$private_key" "$package_path"; do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        printf 'Signing inputs must be regular non-symlink files.\n' >&2
        exit 1
    fi
done

private_key_mode="$(stat -c '%a' "$private_key")"

case "$private_key_mode" in
    400|600)
        ;;
    *)
        printf 'Release private key must use mode 0400 or 0600.\n' >&2
        exit 1
        ;;
esac

if [ -e "$signature_path" ] || [ -L "$signature_path" ]; then
    printf 'Signature output path already exists.\n' >&2
    exit 1
fi

signature_directory="$(dirname "$signature_path")"
mkdir -p "$signature_directory"

temporary_directory="$(mktemp -d)"
temporary_signature="$(mktemp "$signature_directory/.nadi-helper-signature.XXXXXX")"
trap 'rm -rf "$temporary_directory"; rm -f "$temporary_signature"' EXIT

openssl pkey -in "$private_key" -pubout -out "$temporary_directory/release-public.pem"

actual_fingerprint="$(openssl pkey -pubin -in "$temporary_directory/release-public.pem" -outform DER | sha256sum | awk '{print $1}')"

if [ "$actual_fingerprint" != "$expected_fingerprint" ]; then
    printf 'Release private key does not match the pinned NADI trust anchor.\n' >&2
    exit 1
fi

openssl pkeyutl \
    -sign \
    -rawin \
    -inkey "$private_key" \
    -in "$package_path" \
    -out "$temporary_signature"

openssl pkeyutl \
    -verify \
    -pubin \
    -inkey "$temporary_directory/release-public.pem" \
    -rawin \
    -in "$package_path" \
    -sigfile "$temporary_signature" \
    >/dev/null

chmod 0644 "$temporary_signature"
mv "$temporary_signature" "$signature_path"
