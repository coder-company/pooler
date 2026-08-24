# Overview

Pooler is a protocol runtime that runs as one local process. Your AI coding tools point at it instead of at a provider, and Pooler decides which of your accounts serves each request.

It exists because the tools and the accounts do not line up. Cursor, Devin, Factory Droid, Claude Code, and Vercel fx each speak a different wire protocol, while your subscriptions and API keys each have their own quota. Pooler sits between them.

## What it does

**Translates protocols.** Pooler serves OpenAI, Anthropic, Gemini, xAI, Factory, fx, and ConnectRPC routes from one binary. A route either forwards bytes opaquely or performs a bounded semantic translation with an explicit decoder and encoder. Opaque forwarding is never presented as translation.

**Pools accounts.** Declare several accounts in a pool with a selection strategy and a retry policy. When an account hits a quota or cooldown, the next request goes to the next eligible account. Retries are commit-safe: once bytes have been committed to the client, Pooler does not silently replay to a different account.

**Protects credentials.** Sign in with a provider's own device or browser OAuth flow. Tokens are encrypted at rest in SQLite. Configuration references secrets as `env:`, `file:`, or `keyring:` only; a literal secret is rejected, and an API key is never accepted as a command-line value.

**Reports what happened.** A local, authenticated dashboard and management API expose request timelines, provider health, usage, and cost. Everything exposed is metadata. Prompts, responses, request bodies, credentials, and authorization headers are never stored or exported.

**Fails loudly.** Unsupported protocol behavior is rejected rather than silently advertised or discarded. `pooler check` compiles the whole configuration before anything runs, and `pooler preflight` probes connectivity without sending a billable request.

## How the pieces fit

```
      Cursor        Devin      Factory Droid    Claude Code / SDKs
       :8333        :18473        :18474              :8400
         └─────────────┴──────────────┴──────────────────┘
                                │
     ┌──────────────────────────▼───────────────────────────┐
     │                       Pooler                          │
     │                                                       │
     │  ingress          routing            selection        │
     │  decode wire  →   match route    →   pick account     │
     │  or forward       apply policy       honor cooldowns  │
     │                                                       │
     │  encrypted SQLite store   ·   management API :18477    │
     └──────────────────────────┬───────────────────────────┘
                                │
         ┌──────────────┬───────┴───────┬──────────────┐
      ChatGPT /       Claude         Gemini          Grok
    Codex subs       API keys      API + OAuth      API keys
```

## Where things live

Pooler resolves its configuration in this order:

1. an explicit `--config PATH`;
2. `./pooler.yaml` in the current directory;
3. `$XDG_CONFIG_HOME/pooler/pooler.yaml`, normally `~/.config/pooler/pooler.yaml`.

Put the file at the third path and every command works with no flags. Note that `pooler init` does not write there: it scaffolds a new starter directory in the current directory, which you then point at or move.

For a shared machine or server, the hardened systemd layout is fixed instead: the binary at `/usr/local/bin/pooler`, configuration at `/etc/pooler/pooler.yaml`, keys at `/etc/pooler/store.key` and `/etc/pooler/management.key`, and the credential store at `/var/lib/pooler/credentials.sqlite3`. That service binds inference on `127.0.0.1:18400` and management on `127.0.0.1:18401`. See [deployment](deployment.md).

## Default ports

| Surface | Bind |
| :--- | :--- |
| `cursor` preset | `127.0.0.1:8333` |
| `devin` preset | `127.0.0.1:18473` |
| `factory` preset | `127.0.0.1:18474` |
| `fx` preset | `127.0.0.1:18475` |
| `xai` and `media` presets | `127.0.0.1:18476` |
| `gateway` preset | `127.0.0.1:8400` |
| Management, `pooler init` starter | `127.0.0.1:18477` |
| Inference and management, systemd service | `127.0.0.1:18400` and `127.0.0.1:18401` |
| Browser OAuth loopback callback | `http://localhost:1455/auth/callback` |

## Provider login support

Which login methods exist is decided by the provider. Verify with `pooler auth providers` rather than assuming.

| Provider | Aliases | API key | Browser PKCE | Device code |
| :--- | :--- | :---: | :---: | :---: |
| OpenAI | `codex` | Yes | Yes | Yes |
| Google | `gemini` | Yes | Yes | No |
| Anthropic | `claude` | Yes | No | No |
| xAI | `grok` | Yes | No | No |
| Kimi | `moonshot` | Yes | No | Needs operator registration |
| Palantir AIP | `foundry` | No | Needs operator registration | No |

## Where to go next

| Guide | What it covers |
| :--- | :--- |
| [Agent-native setup](agent-native.md) | The prompt you paste into an agent, and the protocol it follows |
| [Quickstart](quickstart.md) | The same setup done by hand |
| [Adapters and presets](adapters-and-presets.md) | Every preset, its parameters, and its port |
| [Gateway](gateway.md) | Route inventory, patch and opaque modes, and model translation |
| [Provider login](provider-login.md) | Device and browser OAuth, endpoint overrides, API-key guidance |
| [Management](management.md) | Management API, request explorer, usage and cost ledger |
| [Configuration management](configuration-management.md) | Schema, imports, typed drafts, and hot reload |
| [Deployment](deployment.md) | Container and systemd deployment |
| [Troubleshooting](troubleshooting.md) | `doctor`, `preflight`, and common failures |
| [CLI reference](cli-reference.md) | Every command and flag |
