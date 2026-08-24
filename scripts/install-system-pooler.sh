#!/usr/bin/env bash

# Install the one canonical Pooler system service. The normal invocation is
# explicit about every input so an installation cannot select an interactive
# user's configuration, keyring, or state directory by accident.

set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/install-system-pooler.sh [options]

Install files into the canonical system layout. The installer is inert with
respect to systemd unless --promote is supplied.

Options:
  --root DIRECTORY          Prefix the system layout (for sandbox fixtures).
  --binary PATH             Release pooler executable.
  --config PATH             Version-2 canonical configuration source.
  --store PATH              Fresh SQLite credential store source.
  --store-key PATH          Store-key source (generated when omitted).
  --management-key PATH     Management bearer source (generated when omitted).
  --unit PATH               Dedicated pooler.service source.
  --backup-root DIRECTORY   Backup root (default: /var/backups/pooler).
  --promote                 Reload and enable --now pooler.service.
  --dry-run                 Validate and report the plan without copying files.
  --no-systemctl            Do not call systemctl (for sandbox fixtures).
  -h, --help                Show this help.
EOF
    exit 2
}

die() {
    printf 'pooler installer: %s\n' "$1" >&2
    exit 1
}

ROOT=/
BINARY=
CONFIG=
STORE=
STORE_KEY=
MANAGEMENT_KEY=
UNIT=
BACKUP_ROOT=/var/backups/pooler
PROMOTE=0
DRY_RUN=0
NO_SYSTEMCTL=0

while (($# > 0)); do
    case "$1" in
        --root) (($# >= 2)) || usage; ROOT=$2; shift 2 ;;
        --binary) (($# >= 2)) || usage; BINARY=$2; shift 2 ;;
        --config) (($# >= 2)) || usage; CONFIG=$2; shift 2 ;;
        --store) (($# >= 2)) || usage; STORE=$2; shift 2 ;;
        --store-key) (($# >= 2)) || usage; STORE_KEY=$2; shift 2 ;;
        --management-key) (($# >= 2)) || usage; MANAGEMENT_KEY=$2; shift 2 ;;
        --unit) (($# >= 2)) || usage; UNIT=$2; shift 2 ;;
        --backup-root) (($# >= 2)) || usage; BACKUP_ROOT=$2; shift 2 ;;
        --promote) PROMOTE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --no-systemctl) NO_SYSTEMCTL=1; shift ;;
        -h|--help) usage ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ "$ROOT" = /* ]] || die '--root must be absolute'
[[ "$BACKUP_ROOT" = /* ]] || die '--backup-root must be absolute'
ROOT=$(printf '%s' "$ROOT" | sed 's:/*$::')
[[ -n "$ROOT" ]] || ROOT=/

root_path() {
    local path=$1
    [[ "$path" = /* ]] || die "canonical path is not absolute: $path"
    if [[ "$ROOT" = / ]]; then
        printf '%s\n' "$path"
    else
        printf '%s%s\n' "$ROOT" "$path"
    fi
}

canonical_binary=$(root_path /usr/local/bin/pooler)
canonical_config=$(root_path /etc/pooler/pooler.yaml)
canonical_store=$(root_path /var/lib/pooler/credentials.sqlite3)
canonical_store_key=$(root_path /etc/pooler/store.key)
canonical_management_key=$(root_path /etc/pooler/management.key)
canonical_unit=$(root_path /etc/systemd/system/pooler.service)
canonical_backup_root=$(root_path "$BACKUP_ROOT")

[[ -n "$BINARY" ]] || BINARY=$canonical_binary
[[ -n "$CONFIG" ]] || CONFIG=$canonical_config
[[ -n "$STORE" ]] || STORE=$canonical_store
[[ -n "$STORE_KEY" ]] || STORE_KEY=$canonical_store_key
[[ -n "$MANAGEMENT_KEY" ]] || MANAGEMENT_KEY=$canonical_management_key
if [[ -z "$UNIT" ]]; then
    script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    UNIT="$script_directory/../deploy/pooler.service"
fi

regular_source() {
    local path=$1
    [[ -f "$path" && ! -L "$path" ]] ||
        die "source is not a regular non-symlink file: $path"
}

validate_config() {
    regular_source "$CONFIG"
    if grep -Eiq 'pooler\.example\.yaml|upstream\.key|downstream\.key|keyring:|0\.0\.0\.0:|\[::\]:' "$CONFIG"; then
        die 'configuration contains an obsolete secret path, keyring reference, or remote bind'
    fi
    grep -Fq '127.0.0.1:18400' "$CONFIG" ||
        die 'configuration must bind inference to 127.0.0.1:18400'
    grep -Fq '127.0.0.1:18401' "$CONFIG" ||
        die 'configuration must bind management to 127.0.0.1:18401'
    grep -Fq 'file:/etc/pooler/management.key' "$CONFIG" ||
        die 'configuration must reference file:/etc/pooler/management.key'
}

validate_unit() {
    regular_source "$UNIT"
    grep -Fq 'User=pooler' "$UNIT" || die 'unit must run as User=pooler'
    grep -Fq 'Group=pooler' "$UNIT" || die 'unit must run as Group=pooler'
    grep -Fq 'UMask=0077' "$UNIT" || die 'unit must set UMask=0077'
    grep -Fq 'ExecStart=/usr/local/bin/pooler --config /etc/pooler/pooler.yaml --credential-store /var/lib/pooler/credentials.sqlite3 --credential-key-ref file:/etc/pooler/store.key serve' "$UNIT" ||
        die 'unit has non-canonical ExecStart arguments'
    if grep -Eiq 'pooler@|upstream\.key|downstream\.key|pooler\.example\.yaml|keyring:' "$UNIT"; then
        die 'unit contains a template, obsolete key, example-config, or keyring dependency'
    fi
}

WORK=$(mktemp -d /tmp/pooler-install.XXXXXX)
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

generate_key_if_missing() {
    local path=$1
    if [[ ! -e "$path" ]]; then
        path="$WORK/$(basename -- "$path")"
        if command -v openssl >/dev/null 2>&1; then
            openssl rand -base64 48 >"$path"
        else
            od -An -N48 -tx1 /dev/urandom | tr -d ' \n' >"$path"
        fi
        chmod 0600 -- "$path"
        printf '%s\n' "$path"
    else
        printf '%s\n' "$path"
    fi
}

STORE_KEY=$(generate_key_if_missing "$STORE_KEY")
MANAGEMENT_KEY=$(generate_key_if_missing "$MANAGEMENT_KEY")

regular_source "$BINARY"
[[ -x "$BINARY" ]] || die "binary is not executable: $BINARY"
validate_config
validate_unit
regular_source "$STORE"
regular_source "$STORE_KEY"
regular_source "$MANAGEMENT_KEY"

SKIP_CHOWN=0
if [[ "$ROOT" != / ]]; then
    # A prefixed root is an isolated fixture, not the host. Keep its exact
    # modes while the redacted manifest records the intended owners.
    SKIP_CHOWN=1
fi
if [[ "$ROOT" = / && "$DRY_RUN" = 0 && "$EUID" -ne 0 ]]; then
    die 'system installation requires root'
fi
if [[ "$ROOT" = / && "$DRY_RUN" = 0 ]] &&
    ! (id pooler >/dev/null 2>&1 && getent group pooler >/dev/null 2>&1); then
    die 'system installation requires the pooler user and group'
fi

if [[ "$DRY_RUN" = 1 ]]; then
    printf 'validated canonical Pooler installation (dry-run; secret values redacted)\n'
    exit 0
fi

make_directory() {
    local path=$1
    local mode=$2
    local owner=$3
    mkdir -p -- "$path"
    chmod "$mode" -- "$path"
    if [[ "$SKIP_CHOWN" = 0 ]]; then
        chown "$owner" -- "$path"
    fi
}

install_file_mode() {
    local source=$1
    local destination=$2
    local mode=$3
    local owner=$4
    local temporary
    temporary="$(dirname -- "$destination")/.pooler-install.$$.tmp"
    rm -f -- "$temporary"
    mkdir -p -- "$(dirname -- "$destination")"
    cp -- "$source" "$temporary"
    chmod "$mode" -- "$temporary"
    if [[ "$SKIP_CHOWN" = 0 ]]; then
        chown "$owner" -- "$temporary"
    fi
    mv -f -- "$temporary" "$destination"
}

make_directory "$(dirname -- "$canonical_backup_root")" 0755 root:root
make_directory "$canonical_backup_root" 0700 root:root
backup_directory="$canonical_backup_root/$(date -u +%Y%m%dT%H%M%SZ)"
suffix=0
while [[ -e "$backup_directory" ]]; do
    suffix=$((suffix + 1))
    backup_directory="$canonical_backup_root/$(date -u +%Y%m%dT%H%M%SZ)-$suffix"
done
make_directory "$backup_directory" 0700 root:root

backup_file() {
    local destination=$1
    local label=$2
    if [[ -f "$destination" && ! -L "$destination" ]]; then
        cp -- "$destination" "$backup_directory/$label"
        chmod 0600 -- "$backup_directory/$label"
        if [[ "$SKIP_CHOWN" = 0 ]]; then
            chown root:root -- "$backup_directory/$label"
        fi
    fi
}

backup_file "$canonical_binary" binary
backup_file "$canonical_config" config
backup_file "$canonical_store" credentials.sqlite3
backup_file "$canonical_store-wal" credentials.sqlite3-wal
backup_file "$canonical_store-shm" credentials.sqlite3-shm
backup_file "$canonical_store_key" store.key
backup_file "$canonical_management_key" management.key
backup_file "$canonical_unit" pooler.service

etc_pooler=$(root_path /etc/pooler)
state_directory=$(root_path /var/lib/pooler)
binary_directory=$(root_path /usr/local/bin)
unit_directory=$(root_path /etc/systemd/system)
make_directory "$etc_pooler" 0770 root:pooler
make_directory "$state_directory" 0700 pooler:pooler
make_directory "$binary_directory" 0755 root:root
make_directory "$unit_directory" 0755 root:root

install_file_mode "$BINARY" "$canonical_binary" 0755 root:root
install_file_mode "$CONFIG" "$canonical_config" 0660 pooler:pooler
install_file_mode "$STORE" "$canonical_store" 0600 pooler:pooler
install_file_mode "$STORE_KEY" "$canonical_store_key" 0640 root:pooler
install_file_mode "$MANAGEMENT_KEY" "$canonical_management_key" 0640 root:pooler
install_file_mode "$UNIT" "$canonical_unit" 0644 root:root

for sidecar in wal shm; do
    source_sidecar="$STORE-$sidecar"
    destination_sidecar="$canonical_store-$sidecar"
    if [[ -f "$source_sidecar" && ! -L "$source_sidecar" ]]; then
        install_file_mode "$source_sidecar" "$destination_sidecar" 0600 pooler:pooler
    else
        rm -f -- "$destination_sidecar"
    fi
done

manifest="$backup_directory/manifest.json"
python3 - "$manifest" "$BINARY" "$CONFIG" "$STORE" "$STORE_KEY" "$MANAGEMENT_KEY" "$UNIT" "$canonical_binary" "$canonical_config" "$canonical_store" "$canonical_store_key" "$canonical_management_key" "$canonical_unit" "$canonical_store-wal" "$canonical_store-shm" <<'PY'
import hashlib
import json
import os
import grp
import pwd
import stat
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
source_paths = sys.argv[2:8]
destination_paths = sys.argv[8:]

def metadata(path_string):
    path = Path(path_string)
    try:
        info = path.stat()
    except FileNotFoundError:
        return {"path": path_string, "present": False}
    return {
        "path": path_string,
        "present": True,
        "bytes": info.st_size,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"),
        "owner": info.st_uid,
        "group": info.st_gid,
        "owner_name": pwd.getpwuid(info.st_uid).pw_name,
        "group_name": grp.getgrgid(info.st_gid).gr_name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }

payload = {
    "format": 1,
    "redacted": True,
    "source": [metadata(path) for path in source_paths],
    "destination": [metadata(path) for path in destination_paths],
    "wal_shm": {
        "source_wal": metadata(source_paths[2] + "-wal"),
        "source_shm": metadata(source_paths[2] + "-shm"),
        "destination_wal": metadata(destination_paths[-2]),
        "destination_shm": metadata(destination_paths[-1]),
    },
}
temporary = manifest_path.with_name(".manifest.json.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
os.replace(temporary, manifest_path)
PY
chmod 0600 -- "$manifest"
if [[ "$SKIP_CHOWN" = 0 ]]; then
    chown root:root -- "$manifest"
fi

if [[ "$PROMOTE" = 1 ]]; then
    [[ "$ROOT" = / ]] || die '--promote is only valid for the real system root'
    [[ "$NO_SYSTEMCTL" = 0 ]] || die '--promote cannot be combined with --no-systemctl'
    systemctl daemon-reload
    systemctl enable --now pooler.service
fi

printf 'installed canonical Pooler files; backup manifest: %s (secret values redacted)\n' "$manifest"
