#!/bin/sh
set -eu

usage() {
    cat >&2 <<'EOF'
usage: scripts/release.sh [options]

Build and package Pooler for the four first-release targets.

Options:
  --target TARGET       Package one target (may be repeated).
  --output DIRECTORY    Write archives and SHA256SUMS there (default: dist).
  --epoch SECONDS       Override SOURCE_DATE_EPOCH.
  --binary PATH         Use an existing target binary instead of compiling.
  --no-repro-check      Skip the second clean build comparison.
  -h, --help            Show this help.
EOF
    exit 2
}

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root_directory=$(CDPATH= cd -- "$script_directory/.." && pwd)
archive_helper=$script_directory/archive.py
sbom_helper=$script_directory/sbom.py
asset_stager=$script_directory/stage-release-assets.sh
assets_manifest=$root_directory/third-party/dashboard-assets/manifest.json
checksum_helper=$script_directory/checksums.sh

targets="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin"
target_count=4
output_directory=$root_directory/dist
provided_binary=
reproducibility_check=1
epoch=${SOURCE_DATE_EPOCH-}

validate_target() {
    target_value=$1
    case "$target_value" in
        ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*|*[!A-Za-z0-9])
            printf 'release target contains unsafe characters or whitespace: %s\n' \
                "$target_value" >&2
            return 1
            ;;
    esac
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --target)
            [ "$#" -ge 2 ] || usage
            validate_target "$2" || exit 2
            if [ "$target_count" -eq 4 ]; then
                targets=
                target_count=0
            fi
            targets="$targets${targets:+ }$2"
            target_count=$((target_count + 1))
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || usage
            output_directory=$2
            shift 2
            ;;
        --epoch)
            [ "$#" -ge 2 ] || usage
            epoch=$2
            shift 2
            ;;
        --binary)
            [ "$#" -ge 2 ] || usage
            provided_binary=$2
            shift 2
            ;;
        --no-repro-check)
            reproducibility_check=0
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            printf 'unknown release option: %s\n' "$1" >&2
            usage
            ;;
    esac
done

[ "$target_count" -gt 0 ] || usage
if [ -n "$provided_binary" ] && [ "$target_count" -ne 1 ]; then
    printf '%s\n' '--binary requires exactly one --target' >&2
    exit 2
fi

for target in $targets; do
    validate_target "$target" || exit 2
done

case "$epoch" in
    '')
        epoch=$(git -C "$root_directory" log -1 --format=%ct)
        ;;
    *[!0-9]*)
        printf 'SOURCE_DATE_EPOCH must be a non-negative integer: %s\n' "$epoch" >&2
        exit 2
        ;;
esac

if [ -z "$epoch" ]; then
    epoch=0
fi

if [ -n "$provided_binary" ] && [ ! -f "$provided_binary" ]; then
    printf 'provided binary is not a regular file: %s\n' "$provided_binary" >&2
    exit 2
fi

mkdir -p "$output_directory"

# Never delete or overwrite a prior release. A fresh output boundary also
# prevents stale archives from being mixed into the new checksum manifest.
for existing_artifact in \
    "$output_directory"/pooler-*.tar.gz \
    "$output_directory"/SHA256SUMS; do
    [ -e "$existing_artifact" ] || [ -L "$existing_artifact" ] || continue
    printf 'release output already contains an artifact: %s\n' \
        "$existing_artifact" >&2
    exit 1
done

work_directory=$(mktemp -d "${TMPDIR:-/tmp}/pooler-release.XXXXXX")
trap 'rm -rf "$work_directory"' EXIT HUP INT TERM

# Disable incremental metadata and remap the checkout path before rustc sees it.
# CARGO_ENCODED_RUSTFLAGS also preserves caller-provided flags without shell
# quoting assumptions.
source_path_flag="--remap-path-prefix=$root_directory=/usr/src/pooler"
build_path_flag="--remap-path-prefix=$work_directory=/usr/src/pooler-build"
separator=$(printf '\037')
if [ -n "${CARGO_ENCODED_RUSTFLAGS-}" ]; then
    export CARGO_ENCODED_RUSTFLAGS="$CARGO_ENCODED_RUSTFLAGS$separator$source_path_flag$separator$build_path_flag"
else
    export CARGO_ENCODED_RUSTFLAGS="$source_path_flag$separator$build_path_flag"
fi
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH=$epoch

metadata_version=$(
    cargo metadata \
        --no-deps \
        --format-version 1 \
        --locked \
        --filter-platform "$(printf '%s\n' "$targets" | awk '{print $1}')" |
        python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
versions = {package["version"] for package in metadata["packages"] if package["name"] == "pooler-cli"}
if len(versions) != 1:
    raise SystemExit("expected exactly one pooler-cli version")
print(next(iter(versions)))
'
)

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    else
        shasum -a 256 -- "$1" | awk '{print $1}'
    fi
}

verify_binary_target() {
    target_value=$1
    binary_path=$2
    command -v file >/dev/null 2>&1 || {
        printf 'file is required to verify a provided binary\n' >&2
        exit 1
    }
    description=$(file -b -- "$binary_path")
    case "$target_value" in
        x86_64-*)
            case "$description" in
                *x86-64*|*x86_64*) ;;
                *)
                    printf 'provided binary architecture does not match %s: %s\n' \
                        "$target_value" "$description" >&2
                    exit 1
                    ;;
            esac
            ;;
        aarch64-*)
            case "$description" in
                *ARM\ aarch64*|*arm64*) ;;
                *)
                    printf 'provided binary architecture does not match %s: %s\n' \
                        "$target_value" "$description" >&2
                    exit 1
                    ;;
            esac
            ;;
        *)
            printf 'cannot verify provided binary architecture for target %s\n' \
                "$target_value" >&2
            exit 2
            ;;
    esac
    case "$target_value" in
        *-unknown-linux-gnu)
            case "$description" in
                *ELF*) ;;
                *)
                    printf 'provided binary format does not match %s: %s\n' \
                        "$target_value" "$description" >&2
                    exit 1
                    ;;
            esac
            ;;
        *-apple-darwin)
            case "$description" in
                *Mach-O*) ;;
                *)
                    printf 'provided binary format does not match %s: %s\n' \
                        "$target_value" "$description" >&2
                    exit 1
                    ;;
            esac
            ;;
    esac
}

build_binary() {
    target=$1
    target_directory=$2
    destination=$3
    mkdir -p "$(dirname "$destination")"
    CARGO_TARGET_DIR=$target_directory cargo build \
        --locked \
        --release \
        --package pooler-cli \
        --bin pooler \
        --target "$target"
    built_binary=$target_directory/$target/release/pooler
    [ -x "$built_binary" ] || {
        printf 'cargo did not produce an executable for %s: %s\n' "$target" "$built_binary" >&2
        exit 1
    }
    cp "$built_binary" "$destination"
    chmod 755 "$destination"
}

for target in $targets; do
    target_safe=$(printf '%s' "$target" | tr '/ ' '__')
    metadata="$work_directory/metadata-$target_safe.json"
    cargo metadata \
        --format-version 1 \
        --locked \
        --filter-platform "$target" \
        >"$metadata"

    cdx="$work_directory/pooler-$target_safe.cdx.json"
    spdx="$work_directory/pooler-$target_safe.spdx.json"
    python3 "$sbom_helper" \
        --metadata "$metadata" \
        --version "$metadata_version" \
        --epoch "$epoch" \
        --target "$target" \
        --assets-manifest "$assets_manifest" \
        --cyclonedx "$cdx" \
        --spdx "$spdx"

    if [ -n "$provided_binary" ]; then
        verify_binary_target "$target" "$provided_binary"
        binary="$work_directory/pooler-$target_safe"
        cp "$provided_binary" "$binary"
        chmod 755 "$binary"
    elif [ "$reproducibility_check" -eq 1 ]; then
        first_binary="$work_directory/pooler-$target_safe.first"
        second_binary="$work_directory/pooler-$target_safe.second"
        build_directory="$work_directory/build-$target_safe"
        build_binary "$target" "$build_directory" "$first_binary"
        rm -rf "$build_directory"
        build_binary "$target" "$build_directory" "$second_binary"
        first_hash=$(hash_file "$first_binary")
        second_hash=$(hash_file "$second_binary")
        if [ "$first_hash" != "$second_hash" ]; then
            printf 'reproducibility check failed for %s\nfirst:  %s\nsecond: %s\n' \
                "$target" "$first_hash" "$second_hash" >&2
            exit 1
        fi
        binary=$first_binary
    else
        binary="$work_directory/pooler-$target_safe"
        build_binary "$target" "$work_directory/build-$target_safe" "$binary"
    fi

    report="$work_directory/MATRIX-$target_safe.md"
    "$binary" fixture report \
        --manifest "$root_directory/fixtures/compatibility/manifest.json" \
        --output "$report"

    package_name="pooler-$metadata_version-$target"
    stage_parent="$work_directory/stage-$target_safe"
    stage="$stage_parent/$package_name"
    mkdir -p "$stage/bin" "$stage/compatibility" "$stage/sbom" \
        "$stage/schema" "$stage/third-party"
    cp "$binary" "$stage/bin/pooler"
    chmod 755 "$stage/bin/pooler"
    cp "$root_directory/README.md" "$stage/README.md"
    cp "$root_directory/LICENSE" "$stage/LICENSE"
    cp "$root_directory/NOTICE" "$stage/NOTICE"
    cp -R "$root_directory/third-party/dashboard-assets" "$stage/third-party/"
    cp "$root_directory/schema/pooler.schema.json" "$stage/schema/pooler.schema.json"
    "$asset_stager" "$root_directory" "$stage"
    cp "$report" "$stage/compatibility/MATRIX.md"
    cp "$root_directory/fixtures/compatibility/manifest.json" "$stage/compatibility/manifest.json"
    cp "$cdx" "$stage/sbom/pooler.cdx.json"
    cp "$spdx" "$stage/sbom/pooler.spdx.json"

    archive="$output_directory/$package_name.tar.gz"
    duplicate_archive="$work_directory/$package_name.duplicate.tar.gz"
    python3 "$archive_helper" --root "$stage" --archive "$archive" --epoch "$epoch"
    python3 "$archive_helper" --root "$stage" --archive "$duplicate_archive" --epoch "$epoch"
    archive_hash=$(hash_file "$archive")
    duplicate_hash=$(hash_file "$duplicate_archive")
    if [ "$archive_hash" != "$duplicate_hash" ]; then
        printf 'archive reproducibility check failed for %s\n' "$target" >&2
        exit 1
    fi
    printf 'packaged %s (%s)\n' "$archive" "$archive_hash"
done

"$checksum_helper" "$output_directory" "$output_directory/SHA256SUMS"
printf 'wrote %s/SHA256SUMS\n' "$output_directory"
