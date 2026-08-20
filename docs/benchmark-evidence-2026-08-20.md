# Release benchmark evidence — 2026-08-20

Environment: Linux x86_64, Rust 1.83.0, release profile. Command:

```sh
POOLER_BENCH_ENFORCE=1 POOLER_BENCH_RUNS=3 \
  scripts/benchmark-release.sh
```

The enforced run completed successfully. The raw JSON report SHA-256 was
`6e2e1f2414a8dc6ba89d910a403333eb61c557d68cf36780c8b0f4f7ae4b0224`.

| Run | Opaque raw p95 | Direct p95 | Proxy overhead p95 | Semantic p95 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 3.670 ms | 2.649 ms | 1.021 ms | 1.832 ms |
| 2 | 3.569 ms | 2.586 ms | 0.982 ms | 1.828 ms |
| 3 | 3.695 ms | 2.699 ms | 0.996 ms | 1.798 ms |

The mixed-protocol stress run lasted 900.191 seconds with 100 clients and
processed 1,009,299 requests. It observed 201,860 independently predicted
failure markers, 126,329 upstream failures, 25,673 failovers, and one explicit
downstream-cancellation propagation. Unexpected failures and panics were zero.
All tracked tasks, permits, refresh leases, temporary files, and secret material
returned to zero. Post-drain RSS (584,925,184 bytes) was below the steady-state
post-warmup baseline (620,503,040 bytes). Every enforced invariant passed.
