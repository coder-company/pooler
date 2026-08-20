# Performance and stress evidence

`pooler-bench` is the deterministic release-gate harness. It is a separate
workspace binary so benchmark setup does not become part of the serving binary.
The opaque measurement starts a real Pooler HTTP listener and a local scripted
TCP upstream with a request and response larger than one MiB. The semantic
measurement decodes and re-encodes a Factory request larger than one MiB, then
converts a fragmented semantic response through the OpenAI Chat and Factory SSE
codecs. The stress workload sends real HTTP requests through one Pooler listener
to a deterministic local upstream, mixes opaque and semantic routes, exercises
credential retry/failover, forces a downstream cancellation, and checks tracked
resource and RSS invariants after drain.

Use the short mode for a fast local or CI smoke check:

```sh
cargo run --release -p pooler-bench -- --short --mode all --json
```

Generate the documented three-run report with:

```sh
scripts/benchmark-release.sh
```

The script runs the opaque and semantic measurements three times and runs the
stress workload once. It writes `target/pooler-benchmark-report.json`. Set
`POOLER_BENCH_SHORT=1` selects short advisory defaults and
`POOLER_BENCH_REPORT=/path/report.json` chooses the output path. The release
script enables enforcement by default; set `POOLER_BENCH_ENFORCE=0` only for
an explicitly advisory local run. Enforced runs reject short or partial
workloads, a failure percentage other than 20%, fewer than three performance
runs, a non-release build, and a dirty worktree.

```sh
POOLER_BENCH_ENFORCE=1 scripts/benchmark-release.sh
```

The full stress defaults are 900 seconds, 10,000 minimum requests, 100
concurrent clients, and 20% deterministic injected upstream failures. Workers
continue until both the duration and minimum-request conditions are satisfied. `--duration-secs`,
`--requests`, `--clients`, `--failure-percent`, and `--seed` make the workload
reproducible and bounded for a lab or CI environment. Failure injection is
derived from `(seed + request_index) mod 100`. The local upstream fails the
first actual upstream attempt for every scheduled request ID. The verifier
compares the exact failed-ID set and failure count with the issued logical
request schedule, then checks issued, processed, observed, retry, and failover
accounting. Predicted markers alone cannot satisfy the gate. The workload does
not depend on an external service.

The performance budgets are opaque loopback overhead p95 below 2 ms with a 1
MiB request and semantic translation p95 below 5 ms for a request at least 1
MiB. Opaque reports retain raw Pooler p50/p95/max, direct-upstream
p50/p95/max, and matched per-request overhead p50/p95/max values used for the
enforced overhead budget. Each overhead sample is the Pooler latency minus the
direct latency from the same iteration; negative deltas are clamped to zero
before percentile calculation. Debug builds are useful for functional smoke
checks but are not
performance evidence; use `--release` for budget measurements. Linux reports
`/proc/self/status` RSS after a concurrent representative warmup and again
after drain plus quiescence sampling. On
platforms without a portable in-process RSS source, the report marks RSS as
unsupported rather than inventing a measurement.

Every report contains a schema version, commit SHA and clean-tree state,
verbose Rust toolchain, host and target, build profile, exact command,
enforcement mode, sample counts, p50/p95/max latency, configured stress
parameters, processed/success/failure counts, peak in-flight clients, observed
upstream requests/failures/failovers/cancellations, RSS measurements,
direct-vs-Pooler latency fields, and named invariant results. Resource current
and peak values come from ownership guards inside the production Pooler server,
drain controller, credential materialization, native refresh, and runtime file
paths; the benchmark does not create placeholder resource leases. The
stress baseline is established after the workload has run through its initial
steady-state half-duration, so allocator growth during startup is not mistaken
for post-drain retention. Keep the JSON report with the commit or release
evidence; do not treat a skipped or unsupported measurement as compatibility
proof.

## CLIProxyAPI comparison

`scripts/benchmark-cliproxyapi.py` compares a release Pooler binary with an
installed CLIProxyAPI binary without using provider credentials or port 8319.
It starts a deterministic loopback OpenAI-compatible upstream, writes
owner-private temporary configurations for both proxies, and removes those
configurations and processes after the run. External HTTP(S) traffic from the
isolated processes is directed to a closed loopback port.

```sh
cargo build --locked --release -p pooler-cli
python3 scripts/benchmark-cliproxyapi.py \
  --samples 240 --warmup 24 --concurrency 8 \
  --output-dir .omo/evidence/cliproxyapi-benchmark
```

Every endpoint receives the same valid 1 MiB OpenAI Chat request and every
response is checked byte-for-byte against the same valid 1 MiB response. The
report retains all raw matched samples plus direct, Pooler, and CLIProxyAPI
p50/p95/max latency. Matched overhead is the signed proxy latency minus direct
latency for the same sample ID. Endpoint order rotates through all six
permutations. This comparison is diagnostic evidence; it does not replace the
release-gate benchmark above.
