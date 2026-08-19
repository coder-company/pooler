# Compatibility fuzz seeds

The files under `corpus/` are small, committed starting inputs for bounded
parser and transform fuzzing. They are intentionally sanitized and contain no
credentials or live-provider traffic.

The SSE, JSON, overlay, and tool-delta seeds are UTF-8 text. Connect seeds use
whitespace-separated hexadecimal bytes because Connect envelopes contain binary
length and flag fields; the replay test decodes that representation before
feeding arbitrary transport fragments to the decoder.

Seed names describe the boundary they exercise. A seed is not a conformance
claim: it only keeps an observed or deliberately adversarial input available
for deterministic replay and future fuzz-target wiring.

The repository also contains a cargo-fuzz package with one target per boundary:

```sh
cargo fuzz run sse fuzz/corpus/sse
cargo fuzz run connect fuzz/corpus/connect
cargo fuzz run json_patch fuzz/corpus/json
cargo fuzz run overlay fuzz/corpus/overlay
cargo fuzz run tool_deltas fuzz/corpus/tool-deltas
```

The Connect target accepts both raw bytes and the hexadecimal seed files in
this repository. Fuzz output is local work product and is not a compatibility
fixture.
