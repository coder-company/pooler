#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
temporary=$(mktemp "${TMPDIR:-/tmp}/pooler-config-schema.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

cd "$repo_dir"
"$script_dir/generate-config-schema.sh" "$temporary"
cmp -s "$temporary" "$repo_dir/schema/pooler.schema.json" || {
    echo "generated config schema differs from schema/pooler.schema.json" >&2
    exit 1
}
