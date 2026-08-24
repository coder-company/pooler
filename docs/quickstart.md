# Quickstart

This guide shows you how to initialize Pooler, connect your ChatGPT / Codex subscription (or provider API key), and connect your coding tools.

## Prerequisites

- Built or installed `pooler` binary (or install via `curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash`).
- A ChatGPT / Codex subscription, or an API key for OpenAI, Claude, Gemini, or Grok.

---

## 1. Initialize a starter deployment

Create an owner-private starter configuration directory:

```sh
pooler init --output pooler-starter
```

The command creates a directory with restricted permissions (`0700` on Unix) containing:
- `pooler.yaml`: Preconfigured, compiler-validated YAML configuration.
- `management.token`: Random bearer token for the management dashboard and API.
- `store.key`: Random master key for the encrypted credential store.
- `provider.key`: Empty file for storing upstream credentials.

---

## 2. Connect your credentials

### Option A: ChatGPT / Codex subscription login (Recommended)

Log in directly using the OAuth device code flow:

```sh
pooler --config pooler-starter/pooler.yaml auth login openai --method device-code
```

Open the displayed browser URL, enter the one-time user code, and authorize. Tokens are encrypted and saved to local SQLite (`AES-GCM`).

*(Alternatively, if you already have Codex CLI credentials on your machine, import them with:)*
```sh
pooler --config pooler-starter/pooler.yaml auth import my-codex --profile codex --from-file ~/.codex/credentials.json
```

### Option B: Provider API key

If using a standard API key, write it to `pooler-starter/provider.key`:

```sh
echo "sk-your-actual-api-key-here" > pooler-starter/provider.key
chmod 0600 pooler-starter/provider.key
```

---

## 3. Validate and run preflight checks

Run compiler and network reachability checks:

```sh
pooler check --config pooler-starter/pooler.yaml
pooler --config pooler-starter/pooler.yaml preflight
```

Preflight verifies DNS, TLS handshakes, and upstream endpoint connectivity with zero inference requests (`inference_requests_sent: 0`).

---

## 4. Start the Pooler runtime

Start the proxy server and management listener:

```sh
pooler --config pooler-starter/pooler.yaml \
  --credential-key-ref file:$(pwd)/pooler-starter/store.key \
  serve
```

Pooler binds:
- Main AI Proxy on `http://127.0.0.1:8319` (or the port defined in your configuration).
- Management Dashboard on `http://127.0.0.1:18477`.

---

## 5. Open the management dashboard

In another terminal, launch the authenticated web dashboard:

```sh
pooler --config pooler-starter/pooler.yaml dashboard
```

The dashboard opens on `http://127.0.0.1:18477`.

---

## 6. Connect your AI coding tools

Point your tools to Pooler:

- **Cursor**: Set OpenAI Base URL to `http://127.0.0.1:8333` (using `imports: [{ preset: cursor }]`).
- **Devin**: Point service URL to `http://127.0.0.1:18473` (using `imports: [{ preset: devin }]`).
- **Factory Droid**: Point AI Base URL to `http://127.0.0.1:18474` (using `imports: [{ preset: factory }]`).
- **OpenAI / Claude SDKs**: Set base URL to `http://127.0.0.1:8319/v1` or `http://127.0.0.1:8400`.

---

## Next steps

- Explore [Agent Native Prompts](agent-native.md) to automate all configuration via your coding agent.
- Learn about [Adapters & Presets](adapters-and-presets.md) for Cursor, Devin, and Factory.
- Set up [Multi-Account Pooling & Failover](management.md#connecting-configured-accounts) to rotate across multiple subscriptions when rate limited.
