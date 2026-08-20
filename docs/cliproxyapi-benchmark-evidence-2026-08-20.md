# Pooler versus CLIProxyAPI benchmark — 2026-08-20

Implementation commit: `ec9b395` (Pooler 0.1.0). Comparison target:
CLIProxyAPI Plus 7.2.125, commit `2e6b1d83`.

Command:

```sh
python3 scripts/benchmark-cliproxyapi.py \
  --samples 240 --warmup 24 --concurrency 8 \
  --output-dir .omo/evidence/cliproxyapi-benchmark-20260820T074835Z
```

Both proxies forwarded identical valid 1,048,576-byte OpenAI Chat Completions
requests to the same deterministic loopback upstream and returned the same
exact 1,048,576-byte response. Endpoint order rotated across all six
permutations. Overhead is the signed proxy latency minus the direct latency for
the same sample ID. No provider credentials or live provider calls were used.

| Path | p50 | p95 | max |
| --- | ---: | ---: | ---: |
| Direct | 7.159 ms | 16.915 ms | 22.533 ms |
| Pooler | 10.974 ms | 21.908 ms | 153.218 ms |
| CLIProxyAPI | 102.712 ms | 127.762 ms | 152.267 ms |
| Pooler matched overhead | 2.996 ms | 13.713 ms | 149.493 ms |
| CLIProxyAPI matched overhead | 94.369 ms | 117.054 ms | 134.980 ms |

All 792 upstream requests had the expected length and SHA-256. Both isolated
proxy processes exited cleanly, temporary configurations were owner-private and
removed, and the existing CLIProxyAPI listener on port 8319 was unchanged. The
raw report SHA-256 was
`a020c5bcf0f17e2ccd55a07a9f3bd6c3fe5fe7477ee95fea701070657ad8728e`.

This comparison measures an OpenAI-compatible translation path under moderate
concurrency. It is diagnostic evidence and does not replace Pooler's release
gate, which separately measures opaque and semantic budgets with its own
matched methodology.
