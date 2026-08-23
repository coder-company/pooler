# pooler

Pooler is a production-oriented protocol runtime for AI clients and providers.
One binary serves composable OpenAI, Anthropic, Gemini, xAI, Factory, fx, and
ConnectRPC routes with opaque forwarding or bounded semantic translation. It
adds model-aware account pooling, brokered OAuth, encrypted persistence,
commit-safe retries, hot configuration, a secured management dashboard, and
release-ready deployment tooling. Compatibility remains explicit: unsupported
protocol behavior is rejected rather than silently advertised or discarded.

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

Create an owner-private first deployment with `pooler init`, run non-billable
provider checks with `pooler preflight`, launch the dashboard with `pooler
dashboard`, or use the management-API-backed `pooler tui`. Secure bootstrap,
typed account creation, brokered device OAuth, client instructions, migration,
and provider verification are documented in [onboarding](docs/onboarding.md).

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

Container and systemd production deployment, owner-private state setup, and
deployment lint/smoke checks are documented in [docs/deployment.md](docs/deployment.md).

See the [gateway architecture](docs/gateway.md),
[compatibility matrix](docs/compatibility-report.md),
[operations guide](docs/deployment.md), and
[release acceptance criteria](docs/release-acceptance.md).
