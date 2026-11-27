#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
    printf 'Usage: %s <package-deb> <expected-version> <expected-architecture>\n' "$0" >&2
    exit 2
fi

package_path="$1"
expected_version="$2"
expected_architecture="$3"

if [ ! -f "$package_path" ] || [ -L "$package_path" ]; then
    printf 'Package must be a regular non-symlink file.\n' >&2
    exit 1
fi

actual_package="$(dpkg-deb --field "$package_path" Package)"
actual_version="$(dpkg-deb --field "$package_path" Version)"
actual_architecture="$(dpkg-deb --field "$package_path" Architecture)"

[ "$actual_package" = "nadi-provision-helper" ]
[ "$actual_version" = "$expected_version" ]
[ "$actual_architecture" = "$expected_architecture" ]

control_directory="$(mktemp -d)"
trap 'rm -rf "$control_directory"' EXIT

dpkg-deb --control "$package_path" "$control_directory"

for script_name in preinst postinst prerm postrm config triggers; do
    if [ -e "$control_directory/$script_name" ]; then
        printf 'Unexpected maintainer script in bootstrap package: %s\n' "$script_name" >&2
        exit 1
    fi
done

file_list="$(dpkg-deb --fsys-tarfile "$package_path" | tar -tf - | grep -v '/$')"
if [ "$file_list" != "./usr/libexec/nadi/nadi-provision" ]; then
    printf 'Bootstrap package contains unexpected files:\n%s\n' "$file_list" >&2
    exit 1
fi

archive_listing="$(dpkg-deb --fsys-tarfile "$package_path" | tar -tvf -)"
if ! printf '%s\n' "$archive_listing" | grep -Eq '^-rwxr-xr-x root/root .* ./usr/libexec/nadi/nadi-provision$'; then
    printf 'Helper archive entry must be root-owned mode 0755.\n' >&2
    exit 1
fi
