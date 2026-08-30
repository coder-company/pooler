# Quickstart

This is the manual path. If you would rather have an agent do it, use [agent-native setup](agent-native.md) instead.

By the end you will have Pooler running locally and one coding tool routed through it.

## 1. Install

System-wide, installing `/usr/local/bin/pooler`:

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | sudo bash
```

Or for your user only, installing `~/.local/bin/pooler`:

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash -s -- --user
```

Confirm the binary runs:

```sh
pooler --version
```

If the command is not found after a per-user install, add `~/.local/bin` to your `PATH`.

## 2. Create a starter configuration

```sh
pooler init --output ./pooler-starter
```

This creates a new directory containing:

- `pooler.yaml`, validated by the compiler before the command reports success;
- `management.token`, a generated management bearer token;
- `store.key`, a generated key for the encrypted credential store;
- `provider.key`, an empty owner-private file for a provider API key.

The directory is mode `0700` and the files are `0600`. The command refuses to overwrite an existing destination.

## 3. Optional: make it the default configuration

Pooler looks for its configuration in this order: an explicit `--config PATH`, then `./pooler.yaml`, then `~/.config/pooler/pooler.yaml`.

Move the file to the last of those and every later command works with no flags:

```sh
mkdir -p ~/.config/pooler
mv ./pooler-starter/pooler.yaml ~/.config/pooler/pooler.yaml
```

If you skip this step, pass `--config ./pooler-starter/pooler.yaml` to every command below.

## 4. Connect an account

Which methods a provider supports is fixed by the provider. Check before you try:

```sh
pooler auth providers
```

### A ChatGPT or Codex subscription

Sign in with the device flow, then confirm the stored credential:

```sh
pooler --credential-key-ref file:$(pwd)/pooler-starter/store.key \
  auth login openai --method device-code

pooler --credential-key-ref file:$(pwd)/pooler-starter/store.key \
  auth status openai
```

Open the printed verification URL and enter the short user code. Tokens are written encrypted to local SQLite.

If you already signed in with the Codex CLI, import that credential instead:

```sh
pooler --credential-key-ref file:$(pwd)/pooler-starter/store.key \
  auth import codex-account --profile codex --from-file ~/.codex/credentials.json
```

### Google Gemini

Gemini uses a loopback browser redirect, by default `http://localhost:1455/auth/callback`:

```sh
pooler --credential-key-ref file:$(pwd)/pooler-starter/store.key \
  auth login google --method oauth
```

### An API key

Anthropic and xAI are API-key only. Export the key and reference it from configuration; Pooler never accepts a key as a command-line value.

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

You can also write a key into `./pooler-starter/provider.key` and reference it with `file:`.

## 5. Verify before you start

```sh
pooler check
pooler preflight
```

`check` compiles the configuration and route plan. `preflight` probes DNS, TLS, endpoint reachability, and configured discovery; it sends no inference request and reports `inference_requests_sent: 0`, so it costs nothing.

Fix any failure before continuing. A passing preflight does not promise quota availability or model correctness.

## 6. Start Pooler

```sh
pooler --credential-key-ref file:$(pwd)/pooler-starter/store.key serve
```

Leave this running. Add `--watch` to reload on configuration changes; on Unix, `SIGHUP` always forces an immediate reload.

## 7. Open the dashboard

In another terminal:

```sh
pooler dashboard
```

The command prints the URL derived from your loopback management bind and opens it. Paste the contents of `management.token` into the browser when asked; the token is never placed in the URL. Use `--no-open` to print the URL only.

For a terminal view instead:

```sh
pooler tui --token-ref file:$(pwd)/pooler-starter/management.token
```

## 8. Route a tool through Pooler

Add a preset for the tool you use, then restart or reload. For Cursor:

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

```sh
pooler check
```

Then set the tool's base URL:

| Tool | Setting |
| :--- | :--- |
| Cursor | OpenAI base URL `http://127.0.0.1:8333` |
| Devin | Service endpoint `http://127.0.0.1:18473` |
| Factory Droid | Base URL `http://127.0.0.1:18474` |
| OpenAI SDKs | `OPENAI_BASE_URL="http://127.0.0.1:8400/v1"` |
| Anthropic SDKs | `ANTHROPIC_BASE_URL="http://127.0.0.1:8400"` |

Some clients require a non-empty API-key field even when they do not need one. Use a non-secret placeholder; Pooler selects the real upstream credential server-side.

Confirm the configured routes and endpoints:

```sh
pooler routes
pooler endpoint-inventory
```

## Next steps

- Add a second account and pool it with failover: [management](management.md).
- Mount a full multi-provider endpoint family: [gateway](gateway.md).
- Run Pooler as a hardened systemd service: [deployment](deployment.md).
- Something broken: [troubleshooting](troubleshooting.md).
