#!/bin/sh
set -eu

usage() {
    printf '%s\n' 'usage: scripts/checksums.sh DIRECTORY [OUTPUT]' >&2
    exit 2
}

directory=${1-}
output=${2-}
[ -n "$directory" ] || usage
[ -d "$directory" ] || {
    printf 'checksum directory does not exist: %s\n' "$directory" >&2
    exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
    hash_command=sha256sum
else
    hash_command='shasum -a 256'
fi

set -- "$directory"/*.tar.gz
if [ "$1" = "$directory/*.tar.gz" ]; then
    printf 'no release archives found in %s\n' "$directory" >&2
    exit 1
fi

checksums=$(mktemp)
trap 'rm -f "$checksums"' EXIT

for archive in "$@"; do
    name=$(basename "$archive")
    if [ "$hash_command" = sha256sum ]; then
        digest=$(sha256sum "$archive" | awk '{print $1}')
    else
        digest=$(shasum -a 256 "$archive" | awk '{print $1}')
    fi
    printf '%s  %s\n' "$digest" "$name" >>"$checksums"
done

if [ -n "$output" ]; then
    output_directory=$(dirname "$output")
    mkdir -p "$output_directory"
    sort "$checksums" >"$output"
else
    sort "$checksums"
fi
