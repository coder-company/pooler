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

The bounded release workflow runs all five targets with
[`scripts/deep-test.sh`](../scripts/deep-test.sh). It also executes the
failure-injection, cancellation, URL-boundary, and redaction suites before
fuzzing. The default local budget is five seconds per target; CI can require
the optional cargo-fuzz and nightly sanitizer toolchains explicitly:

```sh
scripts/deep-test.sh --no-fuzz
POOLER_FUZZ_SECONDS=30 scripts/deep-test.sh
POOLER_REQUIRE_SANITIZER=1 scripts/deep-test.sh --sanitize --no-fuzz
```

Sanitizer runs require a nightly toolchain with `rust-src`. They are skipped
when that toolchain is unavailable locally, unless
`POOLER_REQUIRE_SANITIZER=1` is set. No fuzz artifacts or crash inputs are
written into the committed corpus by the workflow.
