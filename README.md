<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/mark-white-256.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/mark-charcoal-256.png">
  <img alt="Pooler" src="assets/mark-charcoal-256.png" width="84">
</picture>

<h1>Pooler</h1>

<p><strong>by Coder Company</strong></p>

<p>One local endpoint that connects every AI coding tool you use<br>to every model subscription and API key you own.</p>

<p>
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-1c1917?style=flat-square"></a>
  <a href="llms.txt"><img alt="Agent native" src="https://img.shields.io/badge/setup-agent--native-10b981?style=flat-square"></a>
  <a href="Cargo.toml"><img alt="Rust" src="https://img.shields.io/badge/built%20in-Rust-b7410e?style=flat-square"></a>
  <a href="docs/deployment.md"><img alt="Linux and macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-0f766e?style=flat-square"></a>
</p>

<p>
  <a href="#install">Install</a> ·
  <a href="#set-it-up-with-an-agent">Agent setup</a> ·
  <a href="#connect-your-accounts">Accounts</a> ·
  <a href="#presets">Presets</a> ·
  <a href="#dashboard">Dashboard</a> ·
  <a href="docs/index.md">Docs</a>
</p>

</div>

---

## What it does

Pooler runs as one local process on your machine. Your coding tools point at it instead of at a provider, and Pooler decides which of your accounts serves each request.

**Every tool, one endpoint.** Cursor, Devin, Factory Droid, Claude Code, Vercel fx, and plain OpenAI, Anthropic, or Gemini SDKs each speak a different wire protocol. Pooler translates them, so a tool built for one provider can reach another.

**172 known providers, plus anything you point it at.** Naming a provider with `known_provider` pulls in its base URL, credential environment variable, discovery parser, request dialect, endpoint families, model aliases, and quota classifier. Nothing is hardcoded to that list: any HTTP or WebSocket endpoint works as a custom upstream, including a private or self-hosted model.

**Rate limits stop being your problem.** Add several subscriptions and API keys to a pool. When one hits a quota or cooldown, Pooler moves the next request to the next eligible account and records why.

**Credentials stay out of your config files.** Sign in with a provider's own OAuth device or browser flow. Tokens are encrypted at rest in local SQLite. Pooler rejects a literal secret in YAML and never accepts an API key as a command-line argument.

**You can see what happened.** `pooler dashboard` opens a local, authenticated view of every request: which account served it, time to first token, retries, quota cooldowns, token counts, and cost.

```
      Cursor        Devin      Factory Droid    Claude Code / SDKs
       :8333        :18473        :18474              :8400
         └─────────────┴──────────────┴──────────────────┘
                                │
                    ┌───────────▼────────────┐
                    │        Pooler          │
                    │  translate · pool ·    │
                    │  encrypt · observe     │
                    └───────────┬────────────┘
                                │
         ┌──────────────┬───────┴───────┬──────────────┐
      ChatGPT /       Claude         Gemini          Grok
    Codex subs       API keys       API + OAuth     API keys
```

---

## Install

System-wide is the default and installs `/usr/local/bin/pooler`:

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | sudo bash
```

Just for your user, with no root, installing `~/.local/bin/pooler`:

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash -s -- --user
```

The installer verifies the release checksum and fails loudly rather than half-installing. To pin a version, pass `--version 0.1.0`. To build from source instead, use `cargo install --git https://github.com/coder-company/pooler.git pooler-cli`.

Running Pooler as a hardened systemd service is a separate, deliberate step. See [deployment](docs/deployment.md).

---

## Set it up with an agent

Pooler is configured by an agent asking you questions, not by you reading a reference manual. Paste this into Cursor, Devin, Claude Code, Codex, or Factory Droid:

```text
Set up Pooler on my machine.

Read https://raw.githubusercontent.com/coder-company/pooler/main/llms.txt first,
then follow the agent protocol at
https://raw.githubusercontent.com/coder-company/pooler/main/docs/agent-native.md

Before you change anything, ask me these questions using your interactive
question tool (one round, multiple choice where possible):

1. Which coding tools should route through Pooler? (Cursor, Devin, Factory
   Droid, Claude Code / Codex, Vercel fx, xAI Grok, or general OpenAI /
   Anthropic / Gemini SDKs)
2. Which accounts should I connect? (ChatGPT / Codex subscription, Google
   Gemini, OpenAI API key, Anthropic Claude API key, xAI Grok API key, Kimi,
   Palantir AIP, or something else)
3. Do I want more than one account pooled with automatic failover when one
   hits a rate limit?
4. Which models and reasoning settings do I want?
5. System-wide install for every user on this machine, or just my user?

Then install Pooler, write the configuration, walk me through signing in,
verify it with `pooler check` and `pooler preflight`, start it, and tell me
the exact base URL to paste into each tool I named.

Never write a literal API key or token into a YAML file or a shell command.
Use env:, file:, or keyring: references only.
```

The agent reads [`llms.txt`](llms.txt), then the step-by-step protocol in [agent-native setup](docs/agent-native.md), which also carries follow-up prompts for pooling accounts, switching accounts, and diagnosing slow requests.

### Prefer to do it yourself

```sh
pooler init --output ./pooler-starter      # scaffolds config + generated secrets, mode 0700
pooler check --config ./pooler-starter/pooler.yaml
pooler --config ./pooler-starter/pooler.yaml preflight
pooler --config ./pooler-starter/pooler.yaml dashboard
```

Move that `pooler.yaml` to `~/.config/pooler/pooler.yaml` and every later command works with no flags at all: `pooler check`, `pooler serve`, `pooler dashboard`. Full walkthrough in the [quickstart](docs/quickstart.md).

---

## Connect your accounts

Which login methods exist is decided by the provider, not by Pooler. Check the shipped matrix with `pooler auth providers`.

| Provider | Aliases | API key | Browser PKCE | Device code |
| :--- | :--- | :---: | :---: | :---: |
| OpenAI | `codex` | Yes | Yes | Yes |
| Google | `gemini` | Yes | Yes | No |
| Anthropic | `claude` | Yes | No | No |
| xAI | `grok` | Yes | No | No |
| Kimi | `moonshot` | Yes | No | Needs your own registration |
| Palantir AIP | `foundry` | No | Needs your own registration | No |

A ChatGPT or Codex subscription signs in headlessly:

```sh
pooler auth login openai --method device-code
```

Google Gemini uses a loopback browser redirect on `http://localhost:1455/auth/callback`:

```sh
pooler auth login google --method oauth
```

Anthropic and xAI are API-key only. Export the key and reference it; never inline it:

```sh
export ANTHROPIC_API_KEY="..."
```

```yaml
upstreams:
  anthropic:
    known_provider: anthropic
    auth:
      secret: env:ANTHROPIC_API_KEY
```

Already signed in with the Codex CLI? Import it instead of signing in again:

```sh
pooler auth import codex-account --profile codex --from-file ~/.codex/credentials.json
```

Details, including operator-owned OAuth registration, in [provider login](docs/provider-login.md).

### Any provider, including your own

The six providers above are the ones with a built-in *login* flow. Credentials are only part of the story: this build also ships endpoint integrations for **172 known providers**, so most only need a key and a name.

```sh
pooler providers                 # all 172
pooler providers --search groq   # narrow it down
```

```yaml
upstreams:
  groq:
    known_provider: groq         # base URL, dialect, discovery, aliases, quota
    auth:
      secret: env:GROQ_API_KEY
```

You are not limited to that list. Point Pooler at any HTTP or WebSocket endpoint, including a private or self-hosted deployment, and choose how the credential is presented:

```yaml
upstreams:
  my-private-llm:
    url: https://llm.internal.example.com
    auth:
      kind: header                 # bearer, bearer_secret, x_api_key, x_goog_api_key, header
      header: x-internal-key
      secret: env:MY_PRIVATE_LLM_KEY
```

Custom upstreams pool, fail over, and appear in the dashboard exactly like known ones. Providers whose endpoint needs an account-specific region, project, or hostname — Azure OpenAI, Bedrock, Vertex — are deliberately absent from the known list rather than shipped as a guessed URL template; configure those as custom upstreams. See [provider catalog](docs/provider-catalog.md).

---

## Presets

A preset mounts the listeners, routes, and translations one client expects, so you never hand-author a route plan.

| Preset | Client | Default bind | `with:` parameters |
| :--- | :--- | :--- | :--- |
| [`cursor`](docs/adapters-and-presets.md#cursor) | Cursor | `127.0.0.1:8333` | `bind`, `upstream_url`, `secret`, `reasoning_effort`, `model_prefix` |
| [`devin`](docs/adapters-and-presets.md#devin) | Devin | `127.0.0.1:18473` | `bind`, `upstream_url`, `secret` |
| [`factory`](docs/adapters-and-presets.md#factory) | Factory Droid | `127.0.0.1:18474` | `bind`, `upstream_url`, `secret` |
| [`fx`](docs/fx.md) | Vercel Labs fx | `127.0.0.1:18475` | `bind`, `upstream_url`, `secret` |
| [`xai`](docs/adapters-and-presets.md#xai) | xAI Grok | `127.0.0.1:18476` | `bind`, `rest_url`, `websocket_url`, `secret` |
| [`media`](docs/adapters-and-presets.md#media) | Media surfaces | `127.0.0.1:18476` | `bind`, `upstream_url`, `secret` |
| [`gateway`](docs/gateway.md) | OpenAI, Anthropic, Gemini SDKs | `127.0.0.1:8400` | `bind`, `provider`, `upstream_url`, `websocket_url`, `secret` |

```yaml
version: 2

imports:
  - preset: cursor
    as: cursor-adapter
    with:
      bind: 127.0.0.1:8333
      reasoning_effort: high
      model_prefix: gpt-
```

Parameter names are validated strictly and differ per preset, so `pooler check` rejects a typo instead of quietly ignoring it. The `xai` preset takes `rest_url`, not `upstream_url`.

---

## Dashboard

```sh
pooler dashboard
```

The command derives the URL from your loopback management bind and prints it. You paste the management bearer token into the browser; it never appears in a URL, a log, or an export.

**Requests** correlates one logical request end to end: admission, route and account selection, every upstream attempt, retries and failover, first event and TTFT, semantic degradation, and completion. **Accounts** shows redacted credential state and lets you enable, disable, or switch accounts. **Usage** reports token and cost ledgers over selectable time ranges. **Operations** triggers a configuration or catalog reload without dropping active connections.

Everything the dashboard and management API expose is metadata. Prompts, responses, request bodies, credentials, and authorization headers are never stored or exported. Prefer a terminal? `pooler tui --token-ref file:/path/to/management.token`.

---

## Documentation

| Guide | What it covers |
| :--- | :--- |
| [Overview](docs/index.md) | How Pooler fits together and what it guarantees |
| [Quickstart](docs/quickstart.md) | Install to first request, by hand |
| [Agent-native setup](docs/agent-native.md) | The paste-in prompt and the agent protocol |
| [Adapters and presets](docs/adapters-and-presets.md) | Every preset, parameter, and port |
| [Gateway](docs/gateway.md) | Route inventory, streaming, and model translation |
| [Provider login](docs/provider-login.md) | Device and browser OAuth, API-key guidance |
| [Management](docs/management.md) | Management API, request explorer, usage ledger |
| [Configuration](docs/configuration-management.md) | Schema, imports, drafts, and hot reload |
| [Deployment](docs/deployment.md) | Container, systemd, and the hardened system layout |
| [Troubleshooting](docs/troubleshooting.md) | `doctor`, `preflight`, and common failures |
| [CLI reference](docs/cli-reference.md) | Every command and flag |
| [`llms.txt`](llms.txt) | Machine-readable index for agents |

---

## Contributing

Pull requests are welcome. Pooler has a strong bias toward provable behavior: documentation is checked against the shipped binary in CI, so an example that does not compile fails the build.

```sh
cargo build -p pooler-cli --bin pooler
cargo run -p pooler-cli -- check --config config/pooler.example.yaml
```

Before opening a pull request, run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
./scripts/check-config-schema.sh
python3 scripts/check-docs-links.py
python3 scripts/check-docs-examples.py --require-binary
./scripts/verify-compatibility-fixtures.py
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the repository layout, how to add a preset or provider, fixture requirements, and the rules that apply to authentication and management code. Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

**Found a vulnerability?** Do not open a public issue. Report it privately through a [security advisory](https://github.com/coder-company/pooler/security/advisories/new). Scope and response targets are in [SECURITY.md](SECURITY.md).

Need help rather than wanting to contribute? See [SUPPORT.md](SUPPORT.md).

## Releases

Reproducible archives, checksums, and SBOMs for all four supported targets:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) scripts/release.sh --output dist
```

Each release publishes per-target `pooler-<version>-<target>.tar.gz` archives, a `SHA256SUMS` manifest with a Sigstore bundle, and CycloneDX and SPDX bills of material. See [release](docs/release.md) and [release acceptance](docs/release-acceptance.md).

---

<div align="center">
<sub>
<a href="docs/index.md">Documentation</a> ·
<a href="CONTRIBUTING.md">Contributing</a> ·
<a href="SECURITY.md">Security</a> ·
<a href="SUPPORT.md">Support</a> ·
<a href="https://github.com/coder-company/pooler/issues">Issues</a>
<br><br>
Apache-2.0 · Copyright 2026 Pooler contributors
</sub>
</div>
