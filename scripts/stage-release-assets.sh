#!/bin/sh
set -eu

usage() {
    printf '%s\n' 'usage: scripts/stage-release-assets.sh REPOSITORY_ROOT STAGE_DIRECTORY' >&2
    exit 2
}

root_directory=${1-}
stage_directory=${2-}
[ -n "$root_directory" ] && [ -n "$stage_directory" ] || usage
[ -d "$root_directory" ] || {
    printf 'release asset root does not exist: %s\n' "$root_directory" >&2
    exit 1
}

mkdir -p "$stage_directory/config" "$stage_directory/deploy" \
    "$stage_directory/docs" "$stage_directory/scripts"

for required_directory in config docs scripts; do
    source_directory="$root_directory/$required_directory"
    if [ -L "$source_directory" ] || [ ! -d "$source_directory" ]; then
        printf 'required release asset directory is missing or unsafe: %s\n' \
            "$source_directory" >&2
        exit 1
    fi
done

copy_regular_asset() {
    source_path=$1
    destination_directory=$2
    if [ -L "$source_path" ]; then
        printf 'refusing symlinked release asset: %s\n' "$source_path" >&2
        exit 1
    fi
    [ -f "$source_path" ] || {
        printf 'required release asset is missing or not a file: %s\n' \
            "$source_path" >&2
        exit 1
    }
    cp "$source_path" "$destination_directory/"
}

config_count=0
for config in "$root_directory"/config/*.example.yaml; do
    [ -e "$config" ] || [ -L "$config" ] || continue
    copy_regular_asset "$config" "$stage_directory/config"
    config_count=$((config_count + 1))
done
[ "$config_count" -gt 0 ] || {
    printf 'no example configurations found under %s/config\n' "$root_directory" >&2
    exit 1
}

deploy_directory="$root_directory/deploy"
if [ -L "$deploy_directory" ] || [ ! -d "$deploy_directory" ]; then
    printf 'deployment asset directory is missing or unsafe: %s\n' \
        "$deploy_directory" >&2
    exit 1
fi
deployment_count=0
# Runtime-mounted directories (deploy/config, deploy/data, deploy/secrets) are
# intentionally ignored; only checked-in example/unit files belong in an
# archive.
for deployment_asset in \
    "$deploy_directory"/*.example.yaml \
    "$deploy_directory"/*.service; do
    [ -e "$deployment_asset" ] || [ -L "$deployment_asset" ] || continue
    [ "$(basename -- "$deployment_asset")" = "pooler@.service" ] && continue
    copy_regular_asset "$deployment_asset" "$stage_directory/deploy"
    deployment_count=$((deployment_count + 1))
done
[ "$deployment_count" -gt 0 ] || {
    printf 'no deployment assets found under %s\n' "$deploy_directory" >&2
    exit 1
}

copy_regular_asset "$root_directory/docs/deployment.md" "$stage_directory/docs"
for required_script in \
    check-deployment-config.py \
    install-system-pooler.sh \
    test-system-install.sh \
    check-staged-secrets.sh \
    release.sh; do
    copy_regular_asset "$root_directory/scripts/$required_script" \
        "$stage_directory/scripts"
done
