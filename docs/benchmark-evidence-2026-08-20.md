# Release benchmark evidence — 2026-08-20

Implementation commit: `60447e8c9b6bd4a77cbf0929913d2b7258725bf2`.
Environment: Linux x86_64, Rust 1.86.0, release profile. Command:

```sh
POOLER_BENCH_ENFORCE=1 POOLER_BENCH_RUNS=3 \
  scripts/benchmark-release.sh
```

The hardened enforced run completed successfully. The committed report is
[`release-benchmark-60447e8.json`](release-benchmark-60447e8.json). Its compact
JSON SHA-256 is
`d1931649b39baab519514fae097097c92c6b3be1398d2927880e655768a573d7`;
the original pretty-printed capture SHA-256 is
`318b61d9223d1e2337406fd4c717bcdd1dfde108a393bb3436f0b1f425e48038`.

| Run | Opaque raw p95 | Direct p95 | Proxy overhead p95 | Semantic p95 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 3.694 ms | 2.734 ms | 1.372 ms | 1.842 ms |
| 2 | 3.812 ms | 2.883 ms | 1.438 ms | 1.938 ms |
| 3 | 3.610 ms | 2.555 ms | 1.237 ms | 1.865 ms |

The mixed-protocol stress run lasted 900.248 seconds with 100 clients and
processed 1,124,100 requests. It observed exactly 224,820 independently
predicted upstream failures (20% of issued logical requests), 55,380 failovers,
and one explicit
downstream-cancellation propagation. Unexpected failures and panics were zero.
All tracked tasks, permits, refresh leases, temporary files, and secret material
returned to zero. Post-drain RSS (596,787,200 bytes) was below the steady-state
post-warmup baseline (600,780,800 bytes). Every enforced invariant passed.
