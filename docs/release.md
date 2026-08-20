# Release artifacts

Pooler releases are built from a tagged commit with the pinned Rust toolchain.
The release helper produces one deterministic `tar.gz` archive for each of:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Every archive contains the `pooler` executable, `README.md`, `LICENSE`,
`NOTICE`, both example configurations, `schema/pooler.schema.json`, the
sanitized compatibility manifest/report, and CycloneDX 1.5 and SPDX 2.3 SBOMs.

## Local build

Install each Rust target before building. From the repository root:

```sh
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) scripts/release.sh --output dist
```

The helper sets `CARGO_INCREMENTAL=0`, preserves deterministic caller flags,
and adds a rustc `--remap-path-prefix` for the checkout. It compiles each
target twice into clean target directories and compares the executable hashes.
It also creates the archive twice and compares archive hashes. A mismatch is a
release failure.

For a fast native packaging smoke test when a release build already exists:

```sh
host=$(rustc -vV | awk '/^host:/{print $2}')
scripts/release.sh \
  --target "$host" \
  --binary target/release/pooler \
  --output /tmp/pooler-release-smoke
```

`--binary` skips compilation and is for packaging checks only. Published
artifacts must use the default clean-build reproducibility check. `--no-repro-
check` is available for diagnosing a toolchain or linker problem and must not
be used for a release.

`SOURCE_DATE_EPOCH` defaults to the tagged commit timestamp. Set it explicitly
when reproducing a published build. The same value is used for rustc metadata,
archive entries, gzip headers, and SBOM creation timestamps.

## Verification and publication

`SHA256SUMS` is sorted and covers every archive in the output directory. Verify
it before publication:

```sh
(cd dist && sha256sum -c SHA256SUMS)
```

The tag workflow in `.github/workflows/release.yml` runs its Linux jobs on the
organization's custom self-hosted runners. Each Linux job requires all four
labels `[self-hosted, Linux, X64, palantir-actions]`; there is no fallback to a
paid GitHub-hosted Linux runner. The macOS quality lane and the two macOS
release targets remain explicit platform requirements, using
`[self-hosted, macOS, X64, palantir-actions]` for x86_64 and
`[self-hosted, macOS, ARM64, palantir-actions]` for arm64. The configured custom
capacity is currently Linux-only, so matching macOS lanes remain
queued/unavailable and their platform evidence must not be reported as passing.
Ordinary push and pull-request events do not supply `include-macos`, so the
gated job is skipped; reusable callers default the boolean to `false`. The
release workflow passes `include-macos: true`; release acceptance is therefore
still blocked until the required macOS runners are online.

The workflow uploads the archives, generates aggregate checksums, signs the
checksum manifest with Cosign keyless signing, and attaches GitHub build
provenance attestations after all required platform lanes complete.

Publication is blocked until the release acceptance job passes formatting,
Clippy, the workspace tests, `cargo audit`, `cargo deny`, the generated schema
and compatibility-report checks, and the full three-run benchmark plus
15-minute stress workload. The benchmark JSON is retained as a release
workflow artifact alongside the platform build evidence.

The signed checksum manifest is `${TAG}.sigstore.json`. Verify it with the
repository workflow identity before distributing an archive:

```sh
cosign verify-blob \
  --bundle vX.Y.Z.sigstore.json \
  --certificate-identity-regexp \
    'https://github.com/coder-company/pooler/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

GitHub's provenance attestation can be checked independently:

```sh
gh attestation verify pooler-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo coder-company/pooler
```

Compatibility status is copied from the versioned manifest and report. A
sanitized reference fixture is not a current-client or live-provider claim;
the report preserves that distinction in the archive.
