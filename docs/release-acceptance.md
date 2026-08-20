# Release acceptance

The release is accepted only when every required gate below has a recorded,
reproducible result. A green unit-test run alone is not release acceptance.
The current repository status is intentionally pending for external client,
provider, platform, performance, stress, and artifact evidence.

## Local quality gates

Run from the repository root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --deny warnings
cargo deny check
./scripts/check-config-schema.sh
./scripts/check-compatibility-report.sh
```

The schema check compares the checked-in artifact with the deterministic
`pooler config schema` command. The compatibility check compares the checked-in
matrix with the sorted report generated from its versioned manifest.

## Required evidence

| Area | Acceptance evidence | Current caveat |
| --- | --- | --- |
| Configuration | `schema/pooler.schema.json` is regenerated and checked; `pooler check` accepts the examples and rejects unknown fields. | Schema validation does not replace semantic reference and route checks. |
| Compatibility | Every committed fixture replays with zero unexplained differences; `fixtures/compatibility/MATRIX.md` is regenerated. | Sanitized local/cross-language rows do not claim current-client compatibility. |
| Client conformance | Current Cursor, Factory, and Devin client conversations are captured, sanitized, replayed, and linked to matrix rows. | Current-client evidence is still pending for rows marked `not_established` or reference-only. |
| Provider conformance | Live authorization and provider-policy evidence is recorded without secrets. | No live provider authorization is committed. |
| Security | Secret-redaction, owner-only storage, cancellation, dependency, license, and vulnerability gates pass. | `cargo audit`/`cargo deny` results must be recorded for the release commit. |
| Performance | Three consecutive documented 1 MiB benchmark runs meet opaque p95 < 2 ms and semantic p95 < 5 ms. | Benchmark evidence is not implied by functional tests. |
| Stress | Reproducible 15-minute mixed-protocol run processes at least 10,000 requests at 100 clients with 20% deterministic failures, drains cleanly, and meets RSS budget. | Stress evidence remains a separate release gate. |
| Artifacts | Linux x86_64/ARM64 and macOS ARM64/x86_64 binaries, checksums, signatures, SBOM, and provenance are published. | Platform and artifact evidence is pending until release automation runs. |
| Extension boundary | An extension can inspect/transform under explicit capabilities and resource limits without credential/process-memory access; crash/exhaustion isolation is demonstrated. | The Phase 8 extension implementation and its isolation evidence remain pending. |

## Compatibility claims

The only publishable claim is the status in the matrix. A route name, preset
name, protocol string, or passing structural fixture never upgrades a row. If
required semantics are not represented, the route must reject before upstream
execution or explicitly record the configured preserve/degrade policy.

## Release record

The release record should include the commit, toolchain, host/target matrix,
commands and outputs for every gate, fixture manifest digest, benchmark and
stress logs, artifact checksums/signatures/SBOM, and the compatibility evidence
links. Do not include credentials, raw provider bodies, or owner-private
capture material.
