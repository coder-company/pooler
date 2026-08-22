# Release benchmark evidence — 2026-08-22

Accepted implementation commit: `9313fa1b09510f087ec5bd1851cc2c7109fac7bb`.
Environment: Linux x86_64, Rust 1.88.0, release profile, clean worktree.
Command:

```sh
POOLER_BENCH_ENFORCE=1 POOLER_BENCH_RUNS=3 \
  CARGO_TARGET_DIR=/tmp/pooler-target \
  scripts/benchmark-release.sh
```

The enforced run completed successfully. The committed report is [`release-benchmark-9313fa1.json`](release-benchmark-9313fa1.json), SHA-256 `f855de163ec2e8dd4b096b29d0b42143af1c808b13c96287cf2ef0202a26826e`.

| Run | Opaque raw p95 | Direct p95 | Proxy overhead p95 | Semantic p95 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 3.792 ms | 2.630 ms | 1.486 ms | 0.917 ms |
| 2 | 3.663 ms | 2.568 ms | 1.413 ms | 0.939 ms |
| 3 | 3.857 ms | 2.643 ms | 1.547 ms | 1.207 ms |

All three matched opaque-overhead p95 values were below the enforced 2 ms budget. All semantic p95 values were below the enforced 5 ms budget.

The mixed-protocol stress run lasted 900.257 seconds with 100 clients and processed 875,400 logical requests, including 787,860 successful streams and 87,540 deterministic logical failures. It observed the exact expected 175,080 upstream failures, 87,540 retries, 43,903 failovers, and one explicit cancellation. Unexpected failures, panics, deadlocks, leaks, and timeouts were zero. All tracked tasks, permits, refresh leases, temporary files, and secret material returned to zero. RSS changed by 0.724%, within budget. Every enforced invariant passed.

Exact-SHA hosted evidence for `9313fa1` also passed: CI run `32596098683`, Hardening run `32596098727`, and Secret Scan run `32596098981`.

This remains valid historical evidence for implementation commit `9313fa1`; it is not release acceptance for a later documentation, endpoint, recovery, or artifact commit. The eventual release candidate must repeat the enforced benchmark and exact-SHA hosted gates without editing the measured worktree.
