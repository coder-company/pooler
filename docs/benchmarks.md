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
`POOLER_BENCH_SHORT=1` for short defaults, `POOLER_BENCH_REPORT=/path/report.json`
to choose the output path, or `POOLER_BENCH_ENFORCE=1` to fail when a p95 or
stress invariant is outside its budget. A release evidence run should use the
default full workload with enforcement enabled:

```sh
POOLER_BENCH_ENFORCE=1 scripts/benchmark-release.sh
```

The full stress defaults are 900 seconds, 10,000 minimum requests, 100 concurrent
clients, and 20% deterministic failure markers. Workers continue until both the
duration and minimum-request conditions are satisfied. `--duration-secs`,
`--requests`, `--clients`, `--failure-percent`, and `--seed` make the workload
reproducible and bounded for a lab or CI environment. Failure injection is
derived from `(seed + request_index) mod 100`; the report computes the expected
marker count independently from the issued request IDs and compares it with
the IDs observed by the scripted upstream. The local upstream fails marked
primary attempts and the real Pooler retry path records fallback successes. It
does not depend on an external service.

The performance budgets are opaque loopback overhead p95 below 2 ms with a 1
MiB request and semantic translation p95 below 5 ms for a request at least 1
MiB. Opaque reports retain raw Pooler p50/p95/max, direct-upstream
p50/p95/max, and the percentile subtraction used for the enforced overhead
budget. Debug builds are useful for functional smoke checks but are not
performance evidence; use `--release` for budget measurements. Linux reports
`/proc/self/status` RSS after a concurrent representative warmup and again
after drain plus quiescence sampling. On
platforms without a portable in-process RSS source, the report marks RSS as
unsupported rather than inventing a measurement.

Every report contains a schema version, sample counts, p50/p95/max latency,
configured stress parameters, processed/success/failure counts, peak in-flight
clients, observed upstream requests/failures/failovers/cancellations,
task/permit/refresh-lease/temporary-file/secret-material counters, RSS
measurements, direct-vs-Pooler latency fields, and named invariant results. The
stress baseline is established after the workload has run through its initial
steady-state half-duration, so allocator growth during startup is not mistaken
for post-drain retention. Keep the JSON report with the commit or release
evidence; do not treat a skipped or unsupported measurement as compatibility
proof.
