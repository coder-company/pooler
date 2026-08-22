# Pooler versus CLIProxyAPI benchmark — 2026-08-22

Implementation commit: `50f9e6668fbe5f2b23294b3e28b9af66b2f7a86d` (Pooler 0.1.0). Comparison target: CLIProxyAPI Plus 7.2.125, commit `2e6b1d83`.

Command:

```sh
CARGO_TARGET_DIR=/tmp/pooler-target cargo build --locked --bin pooler
python3 scripts/benchmark-cliproxyapi.py \
  --pooler-bin /tmp/pooler-target/debug/pooler \
  --cliproxy-bin /home/chaitanya/.local/bin/cliproxyapi-plus \
  --samples 240 --warmup 24 --concurrency 8 \
  --output-dir /tmp/cliproxyapi-benchmark-50f9e66-exact
```

Both proxies forwarded identical valid 1,048,576-byte OpenAI Chat Completions requests to the same deterministic loopback upstream and returned the exact 1,048,576-byte response. Endpoint order rotated across all six permutations. Overhead is signed proxy latency minus direct latency for the same sample ID. No provider credentials or live-provider calls were used.

| Path | p50 | p95 | max |
| --- | ---: | ---: | ---: |
| Direct | 8.705 ms | 19.760 ms | 32.697 ms |
| Pooler | 18.211 ms | 32.213 ms | 152.208 ms |
| CLIProxyAPI | 112.429 ms | 144.135 ms | 199.670 ms |
| Pooler matched overhead | 8.405 ms | 23.018 ms | 146.597 ms |
| CLIProxyAPI matched overhead | 101.260 ms | 133.843 ms | 191.925 ms |

Pooler's matched p50 overhead was 12.05 times lower than CLIProxyAPI's in this run. Its matched p95 overhead was 5.81 times lower. These are measurements of this run, not universal performance claims.

All 792 upstream requests had the expected length and SHA-256. Both isolated proxy processes exited cleanly, temporary configurations were removed, and the pre-existing CLIProxyAPI listener on port 8319 was unchanged. The tested Pooler binary SHA-256 was `f8110bd8df5c2436f6fe55798e496b9a6c756ab5a72f425b32384549aaae120e`. The raw report SHA-256 was `f300c2ff455afad0f3cf608808786d049e3d2c4f85869f4510647f5c9879f5fe`.

This loopback comparison is diagnostic evidence for implementation commit `50f9e66`. It does not establish live-provider behavior, released-artifact provenance, or acceptance for a later commit. Pooler's release gate separately measures opaque and semantic budgets with matched methodology on the exact release candidate.
