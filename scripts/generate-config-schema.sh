#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
output=${1:-$repo_dir/schema/pooler.schema.json}

cd "$repo_dir"
cargo run --quiet -p pooler-cli -- config schema --output "$output"
