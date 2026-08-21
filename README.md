# pooler

Pooler is a composable protocol runtime for AI clients and providers. It currently
supports strict configuration, opaque HTTP proxying, bounded JSON patch routes,
model-based routing, and composable imports and overlays. Unsupported protocol
compatibility is not advertised.

Validate the example configuration with:

```sh
cargo run -p pooler-cli -- check --config config/pooler.example.yaml
```

Render a fully expanded configuration, including imports and presets, with:

```sh
cargo run -p pooler-cli -- --config config/cursor.example.yaml config render
```

Mount the endpoint families a general OpenAI, Anthropic, or Gemini client
expects, without hand-authoring a route plan, with the
[`gateway` preset](docs/gateway.md):

```sh
POOLER_GATEWAY_KEY=... cargo run -p pooler-cli -- serve --config config/gateway.example.yaml
```

Run the native Vercel Labs fx adapter, including model discovery, streaming,
and tool-result continuation, with the [`fx` preset](docs/fx.md). Factory Droid
is a separate client and does not use this adapter.

Run the opaque proxy with:

```sh
POOLER_UPSTREAM_KEY=... cargo run -p pooler-cli -- serve --config config/pooler.example.yaml
```

Inspect provider login support, aliases, and API-key guidance with `pooler auth
providers`; the secure profile, OAuth override, device-flow, and status UX is
documented in [provider login](docs/provider-login.md). The authenticated account controls,
runtime model controls, reload trigger, traces, audit log, usage/cost views, and redacted
diagnostic export are documented in [operational management](docs/management.md).

Verify every declared compatibility fixture through its adapter or runtime
boundary:

```sh
./scripts/verify-compatibility-fixtures.py
```

Generate and check the strict source-configuration schema:

```sh
./scripts/check-config-schema.sh
```

Capture a structured fixture to an owner-private file. Bodies are omitted by
default; retaining bounded, recursively redacted JSON bodies requires the
explicit flag:

```sh
cargo run -p pooler-cli -- fixture capture input.json capture.json --include-bodies
```

Build reproducible release archives, checksums, and SBOMs for the four supported
release targets with:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) scripts/release.sh --output dist
```

The archive layout and signing/provenance hooks are documented in
[docs/release.md](docs/release.md).

See the [delivery index](pooler-readgold.md), [product goal](GOAL.md), and
[architecture plan](ARCHITECTURE_PLAN.md), [compatibility evidence](docs/compatibility-report.md),
and [release acceptance](docs/release-acceptance.md).
