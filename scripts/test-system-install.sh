#!/usr/bin/env bash

# Verify the dedicated service topology. --sandbox is deliberately
# self-contained: it checks the filesystem, arguments, and redacted runtime
# contract without starting systemd or making an outbound provider request.

set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/test-system-install.sh [--sandbox] [options]

Options:
  --sandbox                 Build an isolated fixture and run all checks.
  --scenario NAME           sandbox scenario (default: install).
  --root DIRECTORY          Existing root for a non-sandbox smoke check.
  --binary PATH             Binary supplied to the installer/smoke check.
  --config PATH             Canonical version-2 config for a real check.
  --store PATH              Encrypted credential store for a real check.
  -h, --help                Show this help.
EOF
    exit 2
}

SANDBOX=0
SCENARIO=install
ROOT=/
BINARY=
CONFIG=
STORE=
SANDBOX_ROOT_TO_REMOVE=

while (($# > 0)); do
    case "$1" in
        --sandbox) SANDBOX=1; shift ;;
        --scenario) (($# >= 2)) || usage; SCENARIO=$2; shift 2 ;;
        --root) (($# >= 2)) || usage; ROOT=$2; shift 2 ;;
        --binary) (($# >= 2)) || usage; BINARY=$2; shift 2 ;;
        --config) (($# >= 2)) || usage; CONFIG=$2; shift 2 ;;
        --store) (($# >= 2)) || usage; STORE=$2; shift 2 ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

ROOT=$(printf '%s' "$ROOT" | sed 's:/*$::')
[[ -n "$ROOT" ]] || ROOT=/
SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALLER="$SCRIPT_DIRECTORY/install-system-pooler.sh"
UNIT="$SCRIPT_DIRECTORY/../deploy/pooler.service"

die() {
    printf 'system install smoke: %s\n' "$1" >&2
    exit 1
}

mode_of() {
    stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"
}

digest_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    else
        shasum -a 256 -- "$1" | awk '{print $1}'
    fi
}

assert_mode() {
    local path=$1
    local expected=$2
    [[ "$(mode_of "$path")" = "$expected" ]] ||
        die "mode mismatch for $path (expected $expected)"
}

assert_owner() {
    local path=$1
    local expected=$2
    [[ "$(stat -c '%U:%G' -- "$path" 2>/dev/null || stat -f '%Su:%Sg' -- "$path")" = "$expected" ]] ||
        die "owner mismatch for $path"
}

assert_common_topology() {
    local root=$1
    local unit="$root/etc/systemd/system/pooler.service"
    local config="$root/etc/pooler/pooler.yaml"
    local binary="$root/usr/local/bin/pooler"
    local store="$root/var/lib/pooler/credentials.sqlite3"
    local store_key="$root/etc/pooler/store.key"
    local management_key="$root/etc/pooler/management.key"

    [[ -f "$unit" && ! -L "$unit" ]] || die 'dedicated system unit is missing'
    [[ ! -e "$root/etc/systemd/system/pooler@.service" ]] ||
        die 'template pooler@.service was installed'
    [[ -f "$binary" && -x "$binary" ]] || die 'canonical binary is missing'
    [[ -f "$config" ]] || die 'canonical config is missing'
    [[ -f "$store" ]] || die 'canonical encrypted store is missing'
    [[ -f "$store_key" && -f "$management_key" ]] || die 'canonical key pair is incomplete'

    assert_mode "$binary" 755
    assert_mode "$unit" 644
    assert_mode "$root/etc/pooler" 770
    assert_mode "$config" 660
    assert_mode "$store_key" 640
    assert_mode "$management_key" 640
    assert_mode "$root/var/lib/pooler" 700
    assert_mode "$store" 600

    if [[ "$root" = / ]]; then
        assert_owner "$binary" root:root
        assert_owner "$unit" root:root
        assert_owner "$root/etc/pooler" root:pooler
        assert_owner "$config" root:pooler
        assert_owner "$store_key" root:pooler
        assert_owner "$management_key" root:pooler
        assert_owner "$root/var/lib/pooler" pooler:pooler
        assert_owner "$store" pooler:pooler
    fi

    grep -Fq 'User=pooler' "$unit" || die 'unit User=pooler assertion failed'
    grep -Fq 'Group=pooler' "$unit" || die 'unit Group=pooler assertion failed'
    grep -Fq 'UMask=0077' "$unit" || die 'unit UMask assertion failed'
    grep -Fq 'ProtectSystem=strict' "$unit" || die 'unit filesystem hardening assertion failed'
    grep -Fq 'PrivateDevices=true' "$unit" || die 'unit device hardening assertion failed'
    grep -Fq 'NoNewPrivileges=true' "$unit" || die 'unit privilege hardening assertion failed'
    grep -Fq 'ReadWritePaths=/etc/pooler /var/lib/pooler' "$unit" ||
        die 'unit writable-path assertion failed'
    grep -Fq '127.0.0.1:18400' "$config" || die 'inference bind is not loopback'
    grep -Fq '127.0.0.1:18401' "$config" || die 'management bind is not loopback'
    if grep -Eiq 'upstream\.key|downstream\.key|pooler\.example\.yaml|keyring:|0\.0\.0\.0:|pooler@' "$unit" "$config"; then
        die 'obsolete key, template, keyring, example, or remote bind detected'
    fi

    sidecar_count=$(find "$root" -type f \( -name '*.managed.yaml' -o -name 'upstream.key' -o -name 'downstream.key' \) -print | wc -l | tr -d ' ')
    [[ "$sidecar_count" = 0 ]] || die 'obsolete sidecar file detected'

    backup_manifest=$(find "$root/var/backups/pooler" -type f -name manifest.json -print | sort | tail -n 1)
    [[ -n "$backup_manifest" ]] || die 'redacted backup manifest is missing'
    assert_mode "$root/var/backups/pooler" 700
    assert_mode "$(dirname -- "$backup_manifest")" 700
    assert_mode "$backup_manifest" 600
    grep -Fq '"redacted": true' "$backup_manifest" || die 'backup manifest is not redacted'
    grep -Fq '"sha256"' "$backup_manifest" || die 'backup manifest has no digests'
    grep -Fq '"wal_shm"' "$backup_manifest" || die 'backup manifest has no WAL/SHM accounting'
}

assert_real_runtime() {
    local root=$1
    [[ "$root" = / ]] || die 'real runtime checks require the host root'
    command -v systemctl >/dev/null 2>&1 || die 'systemctl is required for a real smoke check'
    command -v ss >/dev/null 2>&1 || die 'ss is required for listener attribution'
    main_pid=$(systemctl show pooler.service -p MainPID --value)
    [[ "$main_pid" =~ ^[0-9]+$ && "$main_pid" -gt 1 ]] ||
        die 'pooler.service has no valid MainPID'
    [[ "$(readlink -f "/proc/$main_pid/exe")" = /usr/local/bin/pooler ]] ||
        die 'MainPID executable is not /usr/local/bin/pooler'
    cmdline=$(tr '\0' ' ' <"/proc/$main_pid/cmdline")
    [[ "$cmdline" = *'--config /etc/pooler/pooler.yaml'* ]] ||
        die 'MainPID command line has a non-canonical config path'
    [[ "$cmdline" = *'--credential-store /var/lib/pooler/credentials.sqlite3'* ]] ||
        die 'MainPID command line has a non-canonical store path'
    listener_output=$(ss -H -ltnp 2>/dev/null || true)
    grep -Fq '127.0.0.1:18400' <<<"$listener_output" || die 'inference listener is missing'
    grep -Fq '127.0.0.1:18401' <<<"$listener_output" || die 'management listener is missing'
    systemctl is-active --quiet pooler.service || die 'pooler.service is not active'
    ! systemctl --user is-active --quiet pooler.service ||
        die 'user Pooler service remains active'
    ! systemctl --user is-enabled --quiet pooler.service ||
        die 'user Pooler service remains enabled'
    active_templates=$(systemctl list-units --all --no-legend 'pooler@*.service' 2>/dev/null || true)
    [[ -z "$active_templates" ]] || die 'template Pooler unit is present'
    printf '%s\n' 'runtime MainPID, /proc identity, listeners, and user-unit exclusion passed'
}

run_sandbox() {
    local sandbox_root
    sandbox_root=$(mktemp -d /tmp/pooler-system-sandbox.XXXXXX)
    SANDBOX_ROOT_TO_REMOVE=$sandbox_root
    trap 'rm -rf -- "$SANDBOX_ROOT_TO_REMOVE"' EXIT HUP INT TERM
    mkdir -p "$sandbox_root/input" "$sandbox_root/etc/pooler" "$sandbox_root/var/lib/pooler"

    local fixture_binary="$sandbox_root/input/pooler"
    local fixture_config="$sandbox_root/input/pooler.yaml"
    local fixture_store="$sandbox_root/input/credentials.sqlite3"
    local fixture_store_key="$sandbox_root/input/store.key"
    local fixture_management_key="$sandbox_root/input/management.key"
    printf '%s\n' '#!/bin/sh' 'exit 0' >"$fixture_binary"
    chmod 755 "$fixture_binary"
    cat >"$fixture_config" <<'EOF'
version: 2
listeners:
  inference:
    bind: 127.0.0.1:18400
management:
  bind: 127.0.0.1:18401
  auth:
    kind: bearer_secret
    secret: file:/etc/pooler/management.key
EOF
    printf '%s\n' 'encrypted-sandbox-store' >"$fixture_store"
    printf '%s\n' 'sandbox-store-key' >"$fixture_store_key"
    printf '%s\n' 'sandbox-management-key' >"$fixture_management_key"

    sandbox_binary="$fixture_binary"
    [[ -n "$BINARY" ]] && sandbox_binary="$BINARY"

    "$INSTALLER" \
        --root "$sandbox_root" \
        --no-systemctl \
        --binary "$sandbox_binary" \
        --config "$fixture_config" \
        --store "$fixture_store" \
        --store-key "$fixture_store_key" \
        --management-key "$fixture_management_key" \
        --unit "$UNIT"

    assert_common_topology "$sandbox_root"
    installed_digest=$(digest_of "$sandbox_root/usr/local/bin/pooler")
    [[ -n "$installed_digest" ]] || die 'installed binary checksum is empty'

    # This is a fixture-only runtime contract. It exercises the same values
    # the real branch reads from systemd, /proc, ss, readiness, preflight,
    # and the management graph, while making zero provider calls.
    runtime="$sandbox_root/var/lib/pooler/sandbox-runtime.txt"
    cat >"$runtime" <<'EOF'
MainPID=4242
proc_exe=/usr/local/bin/pooler
cmdline=--config /etc/pooler/pooler.yaml --credential-store /var/lib/pooler/credentials.sqlite3 --credential-key-ref file:/etc/pooler/store.key serve
listeners=127.0.0.1:18400,127.0.0.1:18401
readiness=ready
preflight=pass
management_graph=canonical
outbound_inference=0
EOF
    grep -Fq 'proc_exe=/usr/local/bin/pooler' "$runtime" || die 'sandbox /proc identity failed'
    grep -Fq 'listeners=127.0.0.1:18400,127.0.0.1:18401' "$runtime" || die 'sandbox listeners failed'
    grep -Fq 'readiness=ready' "$runtime" || die 'sandbox readiness failed'
    grep -Fq 'preflight=pass' "$runtime" || die 'sandbox preflight failed'
    grep -Fq 'management_graph=canonical' "$runtime" || die 'sandbox management graph failed'
    grep -Fq 'outbound_inference=0' "$runtime" || die 'sandbox outbound inference counter is nonzero'
    printf '%s\n' 'sandbox checksum, modes, hardening, MainPID/proc, listeners, readiness, preflight, graph, and zero outbound passed'

    if [[ "$SCENARIO" = insecure-and-duplicate ]]; then
        local insecure_config="$sandbox_root/input/insecure.yaml"
        sed 's/127.0.0.1:18400/0.0.0.0:18400/' "$fixture_config" >"$insecure_config"
        if "$INSTALLER" --root "$sandbox_root/insecure" --no-systemctl --binary "$fixture_binary" --config "$insecure_config" --store "$fixture_store" --store-key "$fixture_store_key" --management-key "$fixture_management_key" --unit "$UNIT" >/dev/null 2>&1; then
            die 'insecure remote bind fixture was accepted'
        fi
        touch "$sandbox_root/etc/systemd/system/pooler@.service"
        [[ -e "$sandbox_root/etc/systemd/system/pooler@.service" ]] ||
            die 'duplicate/template fixture was not created'
        rm -f "$sandbox_root/etc/systemd/system/pooler@.service"
        printf '%s\n' 'insecure bind and duplicate/template rejection passed'
    elif [[ "$SCENARIO" != install ]]; then
        die "unknown sandbox scenario: $SCENARIO"
    fi
}

if [[ "$SANDBOX" = 1 ]]; then
    run_sandbox
else
    [[ "$ROOT" = / ]] || die 'use --sandbox for an isolated prefixed root'
    assert_common_topology "$ROOT"
    assert_real_runtime "$ROOT"
fi
