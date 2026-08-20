#!/usr/bin/env bash

# Run bounded hardening checks locally or in CI.  Optional tools are skipped by
# default so the ordinary developer workflow remains usable; CI can make a
# tool mandatory with the corresponding POOLER_REQUIRE_* variable.

set -Eeuo pipefail

ROOT=$(git rev-parse --show-toplevel)
FUZZ_SECONDS=${POOLER_FUZZ_SECONDS:-5}
FUZZ_TIMEOUT=${POOLER_FUZZ_TIMEOUT:-$((FUZZ_SECONDS + 30))}
SANITIZER=${POOLER_SANITIZER:-}
RUN_FUZZ=1
RUN_SANITIZER=0
RUN_STRESS=0

usage() {
    cat <<'EOF'
Usage: scripts/deep-test.sh [options]

Options:
  --no-fuzz       Skip cargo-fuzz targets.
  --sanitize      Run the optional nightly AddressSanitizer job.
  --stress        Run POOLER_STRESS_COMMAND with a bounded timeout.
  --all           Run fuzzing, sanitization, and stress checks.
  -h, --help      Show this help.

Environment:
  POOLER_FUZZ_SECONDS   Per-target libFuzzer budget (default: 5).
  POOLER_FUZZ_TIMEOUT   Wall-clock timeout per target (default: seconds + 30).
  POOLER_FUZZ_TOOLCHAIN Rust toolchain passed to cargo-fuzz (for example: nightly).
  POOLER_SANITIZER      Sanitizer name (default: address when --sanitize is used).
  POOLER_STRESS_COMMAND Deterministic local stress command for --stress.
  POOLER_STRESS_SECONDS Wall-clock stress budget (default: 900).
  POOLER_REQUIRE_FUZZ   Fail instead of skipping when cargo-fuzz is unavailable.
  POOLER_REQUIRE_SANITIZER
                        Fail instead of skipping when nightly sanitizer support is unavailable.
EOF
}

while (($# > 0)); do
    case "$1" in
        --no-fuzz)
            RUN_FUZZ=0
            ;;
        --sanitize)
            RUN_SANITIZER=1
            ;;
        --stress)
            RUN_STRESS=1
            ;;
        --all)
            RUN_SANITIZER=1
            RUN_STRESS=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if ! [[ "$FUZZ_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "POOLER_FUZZ_SECONDS must be a positive integer" >&2
    exit 2
fi
if ! [[ "$FUZZ_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    echo "POOLER_FUZZ_TIMEOUT must be a positive integer" >&2
    exit 2
fi

run() {
    echo "+ $*"
    "$@"
}

run_bounded() {
    local seconds=$1
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout --foreground --signal=TERM --kill-after=10s "${seconds}s" "$@"
    else
        # libFuzzer receives its own max_total_time below.  macOS does not
        # ship GNU timeout, so the command remains bounded by that flag.
        "$@"
    fi
}

run_workspace_checks() {
    run cargo test --workspace --all-features --locked --test phase8_failure_injection
    run cargo test -p pooler-server --all-features --locked --test failure_injection
    run cargo test --workspace --all-features --locked --test phase8_concurrency
    run cargo test --workspace --all-features --locked --test phase8_security
}

run_fuzz_targets() {
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        if [[ ${POOLER_REQUIRE_FUZZ:-0} == 1 ]]; then
            echo "cargo-fuzz is required but not installed" >&2
            return 1
        fi
        echo "cargo-fuzz is not installed; skipping bounded fuzz targets"
        return 0
    fi

    local target corpus
    local -a cargo_fuzz=(cargo)
    if [[ -n ${POOLER_FUZZ_TOOLCHAIN:-} ]]; then
        cargo_fuzz+=("+${POOLER_FUZZ_TOOLCHAIN}")
    fi
    cargo_fuzz+=(fuzz run)
    cd "$ROOT/fuzz"
    while read -r target corpus; do
        echo "+ cargo fuzz run $target $corpus -- -max_total_time=$FUZZ_SECONDS"
        run_bounded "$FUZZ_TIMEOUT" "${cargo_fuzz[@]}" "$target" "$corpus" -- \
            -max_total_time="$FUZZ_SECONDS" \
            -timeout=5 \
            -rss_limit_mb=512 \
            -print_final_stats=1
    done <<'EOF'
sse corpus/sse
connect corpus/connect
json_patch corpus/json
overlay corpus/overlay
tool_deltas corpus/tool-deltas
decompression corpus/decompression
route_match corpus/routes
reasoning_state corpus/reasoning-state
EOF
    cd "$ROOT"
}

run_sanitizer() {
    local toolchain target
    if ! command -v rustup >/dev/null 2>&1; then
        if [[ ${POOLER_REQUIRE_SANITIZER:-0} == 1 ]]; then
            echo "nightly Rust is required for sanitizer checks but is unavailable" >&2
            return 1
        fi
        echo "nightly Rust is unavailable; skipping sanitizer checks"
        return 0
    fi
    toolchain=$(rustup toolchain list | awk '$1 ~ /^nightly($|-)/ {print $1; exit}')
    if [[ -z "$toolchain" ]]; then
        if [[ ${POOLER_REQUIRE_SANITIZER:-0} == 1 ]]; then
            echo "nightly Rust is required for sanitizer checks but is unavailable" >&2
            return 1
        fi
        echo "nightly Rust is unavailable; skipping sanitizer checks"
        return 0
    fi
    if ! rustup component list --toolchain "$toolchain" --installed | grep -qx 'rust-src'; then
        if [[ ${POOLER_REQUIRE_SANITIZER:-0} == 1 ]]; then
            echo "nightly rust-src is required for sanitizer checks but is unavailable" >&2
            return 1
        fi
        echo "nightly rust-src is unavailable; skipping sanitizer checks"
        return 0
    fi

    SANITIZER=${SANITIZER:-address}
    case "$SANITIZER" in
        address|leak|memory)
            ;;
        *)
            echo "POOLER_SANITIZER must be address, leak, or memory" >&2
            return 2
            ;;
    esac
    target=$(rustc -vV | awk '/^host:/ {print $2}')
    if ! rustup target list --installed --toolchain "$toolchain" | grep -qx "$target"; then
        if [[ ${POOLER_REQUIRE_SANITIZER:-0} == 1 ]]; then
            echo "Rust target $target is not installed for $toolchain" >&2
            return 1
        fi
        echo "Rust target $target is unavailable for $toolchain; skipping sanitizer checks"
        return 0
    fi

    local sanitizer_options
    sanitizer_options='halt_on_error=1:detect_leaks=1:allocator_may_return_null=0'
    run env \
        RUSTFLAGS="-Zsanitizer=$SANITIZER" \
        ASAN_OPTIONS="$sanitizer_options" \
        cargo +"$toolchain" test \
        --workspace \
        --all-features \
        --locked \
        -Zbuild-std=std,panic_abort \
        --target "$target"
}

run_stress() {
    if [[ -z ${POOLER_STRESS_COMMAND:-} ]]; then
        echo "POOLER_STRESS_COMMAND is unset; skipping stress command"
        return 0
    fi
    local seconds=${POOLER_STRESS_SECONDS:-900}
    if ! [[ "$seconds" =~ ^[1-9][0-9]*$ ]]; then
        echo "POOLER_STRESS_SECONDS must be a positive integer" >&2
        return 2
    fi
    echo "+ bounded stress command (${seconds}s)"
    run_bounded "$seconds" bash -c "$POOLER_STRESS_COMMAND"
}

cd "$ROOT"
run_workspace_checks
if ((RUN_FUZZ)); then
    run_fuzz_targets
fi
if ((RUN_SANITIZER)); then
    run_sanitizer
fi
if ((RUN_STRESS)); then
    run_stress
fi

echo "deep hardening checks completed"
