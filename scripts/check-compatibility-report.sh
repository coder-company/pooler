#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
temporary=$(mktemp "${TMPDIR:-/tmp}/pooler-compatibility-report.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

cd "$repo_dir"
cargo run --quiet -p pooler-cli -- fixture report \
    --manifest fixtures/compatibility/manifest.json \
    --output "$temporary"
cmp -s "$temporary" fixtures/compatibility/MATRIX.md || {
    echo "generated compatibility matrix differs from fixtures/compatibility/MATRIX.md" >&2
    exit 1
}
