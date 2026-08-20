#!/usr/bin/env bash

# Run the deterministic release benchmark harness. The stress workload runs
# once; --runs applies to the opaque and semantic measurements so a report
# contains the three consecutive runs required by the release gate.

set -Eeuo pipefail

ROOT=$(git rev-parse --show-toplevel)
REPORT=${POOLER_BENCH_REPORT:-"$ROOT/target/pooler-benchmark-report.json"}
RUNS=${POOLER_BENCH_RUNS:-3}
SHORT=${POOLER_BENCH_SHORT:-0}
ENFORCE=${POOLER_BENCH_ENFORCE:-0}

if ! [[ "$RUNS" =~ ^[1-9][0-9]*$ ]]; then
    echo "POOLER_BENCH_RUNS must be a positive integer" >&2
    exit 2
fi
case "$SHORT" in
    0|1) ;;
    *) echo "POOLER_BENCH_SHORT must be 0 or 1" >&2; exit 2 ;;
esac
case "$ENFORCE" in
    0|1) ;;
    *) echo "POOLER_BENCH_ENFORCE must be 0 or 1" >&2; exit 2 ;;
esac

mkdir -p "$(dirname "$REPORT")"
args=(--mode all --runs "$RUNS" --json --output "$REPORT")
if [[ "$SHORT" == 1 ]]; then
    args+=(--short)
fi
if [[ "$ENFORCE" == 1 ]]; then
    args+=(--enforce-budgets)
fi

cd "$ROOT"
echo "+ cargo run --locked --release -p pooler-bench -- ${args[*]}"
cargo run --locked --release -p pooler-bench -- "${args[@]}"
echo "benchmark report: $REPORT"
