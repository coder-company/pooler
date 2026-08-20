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
