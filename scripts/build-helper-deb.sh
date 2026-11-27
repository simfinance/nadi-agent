#!/usr/bin/env bash
set -euo pipefail

usage()
{
    printf 'Usage: %s <verified-agent-binary> <version> <architecture> <sha256> <output-deb>\n' "$0" >&2
}

if [ "$#" -ne 5 ]; then
    usage
    exit 2
fi

artifact_path="$1"
version="$2"
architecture="$3"
expected_sha256="$4"
output_path="$5"

if [ ! -f "$artifact_path" ] || [ -L "$artifact_path" ]; then
    printf 'Agent artifact must be a regular non-symlink file.\n' >&2
    exit 1
fi

if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
    printf 'Invalid Debian package version.\n' >&2
    exit 1
fi

case "$architecture" in
    amd64|arm64)
        ;;
    *)
        printf 'Unsupported Debian architecture: %s\n' "$architecture" >&2
        exit 1
        ;;
esac

if ! printf '%s' "$expected_sha256" | grep -Eq '^[a-f0-9]{64}$'; then
    printf 'Expected SHA-256 digest is malformed.\n' >&2
    exit 1
fi

if ! printf '%s  %s\n' "$expected_sha256" "$artifact_path" | sha256sum --check --status; then
    printf 'Agent artifact SHA-256 verification failed.\n' >&2
    exit 1
fi

output_directory="$(dirname "$output_path")"
mkdir -p "$output_directory"

package_root="$(mktemp -d)"
trap 'rm -rf "$package_root"' EXIT

install -d -m 0755 "$package_root/DEBIAN"
install -d -m 0755 "$package_root/usr/libexec/nadi"
install -m 0755 "$artifact_path" "$package_root/usr/libexec/nadi/nadi-provision"

cat > "$package_root/DEBIAN/control" <<EOF
Package: nadi-provision-helper
Version: $version
Section: admin
Priority: optional
Architecture: $architecture
Maintainer: NADI Platform
Description: NADI trusted provisioning helper
 Installs the fixed root-owned NADI provisioning helper used by the
 Laravel deployment-user installer. No maintainer scripts are included.
EOF

dpkg-deb --build --root-owner-group "$package_root" "$output_path"
