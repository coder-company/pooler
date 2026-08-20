# Compatibility laboratory

`manifest.json` is the versioned input to the compatibility report. The
checked-in `MATRIX.md` is generated from that manifest and is kept readable for
release review. Run the report command from the repository root:

```sh
cargo run -p pooler-cli -- fixture report \
  --manifest fixtures/compatibility/manifest.json \
  --output fixtures/compatibility/MATRIX.md
```

The manifest records sanitized local or cross-language evidence separately from
current-client and live-provider evidence. A reference row is deliberately not
a compatibility claim. `supported_capabilities` describes the exercised
capability surface; `unsupported_capabilities` records capabilities outside the
fixture or without evidence. Neither field is inferred from a route or preset
name. Add a current-client or provider row only with a reproducible fixture,
provenance, and replay test. See
[`docs/compatibility-report.md`](../../docs/compatibility-report.md) for the
evidence rules and status meanings.

Run every manifest row through its committed adapter, HTTP runtime, or config
compiler verifier with:

```sh
./scripts/verify-compatibility-fixtures.py
```

The gate rejects new or renamed rows until they have an explicit verifier. Each
Rust verifier must begin the mapped test with a local `MANIFEST_FIXTURE`
`include_str!` binding to the exact manifest path. An unrelated include elsewhere
in the source file therefore cannot satisfy the gate. Current-client fixture
envelopes also bind adapter, protocol, version, equivalence, and exercised
capabilities to the manifest claim.
