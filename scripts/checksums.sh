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
    hash_archive() {
        sha256sum -- "$1" | awk '{print $1}'
    }
else
    hash_archive() {
        shasum -a 256 -- "$1" | awk '{print $1}'
    }
fi

for archive in "$directory"/*.tar.gz; do
    [ -e "$archive" ] || [ -L "$archive" ] || continue
    case "$(basename "$archive")" in
        pooler-*.tar.gz) ;;
        *)
            printf 'unexpected non-Pooler archive in %s: %s\n' "$directory" \
                "$(basename "$archive")" >&2
            exit 1
            ;;
    esac
done

set -- "$directory"/pooler-*.tar.gz
if [ "$1" = "$directory/pooler-*.tar.gz" ]; then
    printf 'no release archives found in %s\n' "$directory" >&2
    exit 1
fi

checksums=$(mktemp)
trap 'rm -f "$checksums"' EXIT

for archive in "$@"; do
    # Checksums must cover regular release files only.  Refuse a matching
    # directory or symlink rather than following it into an unexpected path.
    if [ ! -f "$archive" ] || [ -L "$archive" ]; then
        printf 'unsafe release archive path: %s\n' "$archive" >&2
        exit 1
    fi
    name=$(basename "$archive")
    digest=$(hash_archive "$archive")
    printf '%s  %s\n' "$digest" "$name" >>"$checksums"
done

if [ -n "$output" ]; then
    output_directory=$(dirname "$output")
    mkdir -p "$output_directory"
    temporary_output=$(mktemp "$output.tmp.XXXXXX")
    trap 'rm -f "$checksums" "$temporary_output"' EXIT
    LC_ALL=C sort "$checksums" >"$temporary_output"
    mv -f "$temporary_output" "$output"
else
    LC_ALL=C sort "$checksums"
fi
