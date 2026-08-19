# Pooler Read-Gold

This document is the implementation index for Pooler. The normative product scope is
defined by [GOAL.md](GOAL.md), and the architecture, invariants, phases, and exit
criteria are defined by [ARCHITECTURE_PLAN.md](ARCHITECTURE_PLAN.md).

## Delivery contract

Pooler is delivered phase-by-phase. A phase is complete only when its stated exit
criteria are covered by executable tests and all repository quality gates pass.
Unsupported compatibility is reported explicitly; it is never inferred from a route
name or advertised without conformance evidence.

## Current status

- Phase 0 — engineering baseline: implemented; local formatting, Clippy, tests,
  config-check smoke test, and code review pass. Linux/macOS CI evidence is pending
  the pushed commit.
- Phase 1 — opaque custom proxy: implemented and locally verified; cross-platform
  CI evidence is pending the pushed commit.
- Phase 2 — patch and overlay engine: in progress. Bounded JSON inspection,
  transforms, model declarations, runtime patching, and local E2E coverage are
  implemented, including model-based provider selection and upstream-model
  rewriting. Overlays, preset rendering, and Cursor compatibility evidence remain.
- Phases 3–8: pending.
- First useful release acceptance: pending.

## Verification gates

The authoritative local gate is:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --deny warnings
cargo deny check
```

Release performance, stress, security, compatibility, artifact, signature, checksum,
and SBOM evidence will be linked here as those gates become executable.
