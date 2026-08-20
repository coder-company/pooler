# Release benchmark evidence — 2026-08-20

Implementation commit: `47f68b29cc2aa240e35fc470e8cc5c012a1af9fc`.
Environment: Linux x86_64, Rust 1.88.0, release profile. Command:

```sh
POOLER_BENCH_ENFORCE=1 POOLER_BENCH_RUNS=3 \
  scripts/benchmark-release.sh
```

The hardened enforced run completed successfully. The committed report is
[`release-benchmark-47f68b2.json`](release-benchmark-47f68b2.json). The original
pretty-printed capture SHA-256 is
`a4777b01f678078d0c65e4171d734513fafe41c3a7e01c07561c474b9dc7775e`.
The committed compact JSON SHA-256 is
`63a8b766c825d7b4f4f67fef455889147452b4e8da80273549bedad037921ba4`.

| Run | Opaque raw p95 | Direct p95 | Proxy overhead p95 | Semantic p95 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 3.371 ms | 2.371 ms | 1.222 ms | 1.926 ms |
| 2 | 3.381 ms | 2.434 ms | 1.187 ms | 1.921 ms |
| 3 | 3.346 ms | 2.417 ms | 1.175 ms | 3.204 ms |

The mixed-protocol stress run lasted 900.287 seconds with 100 clients and
processed 1,172,800 requests. It observed exactly 234,560 independently
predicted upstream failures (20% of issued logical requests), 57,959 failovers,
and one explicit
downstream-cancellation propagation. Unexpected failures and panics were zero.
All tracked tasks, permits, refresh leases, temporary files, and secret material
returned to zero. Post-drain RSS (570,486,784 bytes) was below the steady-state
post-warmup baseline (596,078,592 bytes). Every enforced invariant passed.
