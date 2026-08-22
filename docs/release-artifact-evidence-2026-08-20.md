# Linux x86_64 release artifact evidence — historical evidence reviewed 2026-08-22

This artifact predates the current implementation and is not a released artifact for commit `50f9e66` or any later release candidate. It proves only that the packaging/reproducibility path worked for the named historical commit and target.

Packaging fix commit: `3917eda`. Toolchain: Rust 1.88.0. Target:
`x86_64-unknown-linux-gnu`.

The release packager built the Pooler executable twice from clean, independent
Cargo target state using the same remapped build path. The executable hashes
matched, closing the Rust 1.88 build-path reproducibility regression. The
verified executable was then staged against the clean packaging commit with:

```sh
SOURCE_DATE_EPOCH=1700000000 scripts/release.sh \
  --target x86_64-unknown-linux-gnu \
  --output /tmp/pooler-final-release-clean \
  --binary target/release/pooler
```

Evidence:

- executable SHA-256:
  `74041aa0ca6a45c8e36b30382333968d6485543f7b42411f7ae3e658eed4104a`
- archive SHA-256:
  `da8eb5b324c10ff438b5af76be62bdac7e9a484b26c0b46b1b1b72d224177c24`
- `sha256sum -c SHA256SUMS`: passed
- CycloneDX 1.5 SBOM: 269 components
- SPDX 2.3 SBOM: 270 packages
- archive contains the executable, README, LICENSE, NOTICE, examples, schema,
  compatibility manifest/report, and both SBOM formats

This proves the historical Linux x86_64 artifact locally. Current Linux x86_64
and ARM64 plus macOS x86_64 and ARM64 artifacts, checksums, signatures, SBOMs,
and hosted provenance remain unfulfilled publication gates. macOS capacity,
signing credentials, and hosted release publication are external blockers in
the current environment; historical hashes cannot satisfy them.
