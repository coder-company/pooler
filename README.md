<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/mark-white-128.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/mark-charcoal-128.png">
  <img alt="Pooler by Coder Company" src="assets/mark-charcoal-128.png" width="88" height="78">
</picture>

# Pooler
**by Coder Company**

### The system-wide protocol daemon and account pooling proxy for AI coding agents.

[![License](https://img.shields.io/badge/license-Apache--2.0-black?style=flat-square)](LICENSE)
[![Built for Agents](https://img.shields.io/badge/agent--native-llms.txt-10B981?style=flat-square)](llms.txt)
[![Rust](https://img.shields.io/badge/runtime-Rust-orange?style=flat-square&logo=rust)](Cargo.toml)
[![Mintlify](https://img.shields.io/badge/docs-Mintlify-059669?style=flat-square)](mint.json)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-blue?style=flat-square)](docs/deployment.md)

[**Quick Install**](#-quick-install) · [**Agent Initiation Prompt**](#-1-agent-native-setup-primary) · [**Subscriptions & APIs**](#-2-connect-subscriptions--provider-apis) · [**Dashboard**](#-management-dashboard) · [**Adapters**](#-adapters--presets) · [**llms.txt**](llms.txt)

---

</div>

## What is Pooler?

**Pooler** is a **system-wide background proxy daemon** that connects your AI coding tools (**Cursor**, **Devin**, **Factory Droid**, **Claude Code**, and terminal SDKs) across all your projects to your **ChatGPT / Codex subscriptions** and **model provider APIs** (OpenAI, Anthropic Claude, Google Gemini, xAI Grok, custom providers).

- **System-wide local proxy**: Install once on your machine. All your projects, repositories, and tools talk to the same background daemon.
- **Account pooling & automatic failover**: Connect multiple subscriptions or API keys. When one hits a rate limit or hourly quota, Pooler switches to the next available account instantly.
- **Brokered OAuth & safe credentials**: Log in with one-click device OAuth or browser PKCE. Credentials stay encrypted in local SQLite (`AES-GCM`) instead of leaking plaintext keys.
- **Real-time web dashboard**: Run `pooler dashboard` to view live request timelines, time-to-first-token (TTFT), cooldowns, token counts, and cost ledgers on `http://127.0.0.1:18477`.

```
+---------------------------------------------------------------------------------------+
|                 Your Machine's Coding Tools & Agents (All Repositories)               |
|        Cursor (:8333) | Devin (:18473) | Factory Droid (:18474) | SDKs (:8400)        |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                           Pooler System-Wide Background Daemon                        |
|  +------------------------------------+  +-----------------------------------------+  |
|  | Protocol & Presets Translation     |  | Multi-Account Pooling & Quota Cooldowns |  |
|  | - JSON Patch (Cursor)              |  | - Fill-first / round-robin selection   |  |
|  | - ConnectRPC Protobuf (Devin)      |  | - Automatic rate-limit retry & failover |  |
|  | - Factory v3/v4 Language Model     |  | - Encrypted SQLite token persistence   |  |
|  +------------------------------------+  +-----------------------------------------+  |
|                                                                                       |
|  +---------------------------------------------------------------------------------+  |
|  | Web Management Dashboard (:18477) · Request Timelines · Real-time Usage Ledger  |  |
|  +---------------------------------------------------------------------------------+  |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                           Your Subscriptions & Provider APIs                          |
|         ChatGPT / Codex Subscriptions | Claude | Gemini | xAI Grok | Custom           |
+---------------------------------------------------------------------------------------+
```

---

## ⚡ Quick Install

Install the standalone Pooler binary system-wide:

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash
```

*Or install via Cargo:*
```sh
cargo install --git https://github.com/coder-company/pooler.git pooler-cli --bin pooler
```

---

## 🤖 1. Agent-Native Setup (Primary)

Pooler is built agent-native. Copy this prompt into your coding agent (**Cursor**, **Devin**, **Claude Code**, **Codex**, or **Factory Droid**):

### Copy-Paste Agent Initiation Prompt:

```text
Set up and configure Pooler system-wide on my machine from https://github.com/coder-company/pooler:
1. First, ask me using your interactive question tool:
   - Which coding tools/agents I use on this machine (Cursor, Devin, Factory Droid, Claude Code / Codex, or general SDKs).
   - What credentials/subscriptions I want to connect (ChatGPT / Codex subscription via device OAuth, Google Gemini OAuth, Anthropic Claude API key, OpenAI API key, xAI Grok, or Custom).
   - Whether I want multi-account pooling with automatic rate-limit failover across my subscriptions.
   - What specific models or reasoning settings I want enabled (e.g. gpt-4o, claude-3-7-sonnet, gemini-2.5-pro, o3-mini with high reasoning).
2. Fetch documentation and recipes from https://raw.githubusercontent.com/coder-company/pooler/main/llms.txt or inspect the repository at https://github.com/coder-company/pooler.
3. Install the Pooler binary if not already present:
   `curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash`
4. Set up the system-wide configuration at ~/.config/pooler/pooler.yaml.
5. Guide me through authenticating my subscriptions (such as running `pooler auth login openai --method device-code` for Codex subscriptions or setting environment variables).
6. Run `pooler check` and `pooler preflight` to verify system-wide setup.
7. Start the system-wide daemon with `pooler serve` and verify with `pooler dashboard`.
8. Provide the exact local connection URLs for all my coding tools.
```

👉 *Detailed autonomous agent protocol and task prompt recipes in [`llms.txt`](llms.txt) and [`docs/agent-native.md`](docs/agent-native.md).*

---

## 🔑 2. Connect Subscriptions & Provider APIs

### Option A: ChatGPT / Codex Subscription (Device OAuth)
```sh
pooler auth login openai --method device-code
```
*Open the verification URL, enter the code, and authorize. Tokens are encrypted in local SQLite.*

### Option B: Google Gemini (Browser PKCE OAuth)
```sh
pooler auth login google --method oauth
```

### Option C: Provider API Keys (Anthropic Claude, OpenAI, xAI Grok)
Set your environment variables or store them in owner-private files (`0600`):
```sh
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export XAI_API_KEY="xai-..."
```

### Option D: 1-Click Login via Web Dashboard
```sh
pooler serve &
pooler dashboard
```
*Go to **Accounts** → **Connect** in the web UI to authenticate subscriptions or add keys.*

---

## 📊 Management Dashboard

Just run:
```sh
pooler dashboard
```

Opens the authenticated management web dashboard on `http://127.0.0.1:18477`:
- **Overview**: Active configuration generation, listener status, route inventory, and health status.
- **Live Request Explorer**: Per-request timeline correlating admission, route selection, TTFT, retries, and token usage.
- **Accounts & Failover**: Manage subscriptions, API keys, OAuth refresh tokens, and pool failover priority.
- **Historical Usage Ledger**: Multidimensional time-range analytics for input/output/reasoning tokens and USD costs.
- **Operations & Hot Reload**: Reload configuration in memory (`POST /reload`) without dropping active connections.

---

## 🔌 Adapters & Presets

| Preset | Target Client | Default Bind | Purpose |
| :--- | :--- | :--- | :--- |
| [`cursor`](docs/adapters-and-presets.md#1-cursor-preset-cursor) | Cursor IDE | `127.0.0.1:8333` | Rewrites model prefixes and injects reasoning effort. |
| [`devin`](docs/adapters-and-presets.md#2-devin-connectrpc-preset-devin) | Devin | `127.0.0.1:18473` | Translates ConnectRPC protobuf to OpenAI completions. |
| [`factory`](docs/adapters-and-presets.md#3-factory-droid-preset-factory) | Factory Droid | `127.0.0.1:18474` | Translates `/v3/ai` and `/v4/ai` endpoints. |
| [`gateway`](docs/gateway.md) | Multi-provider | `127.0.0.1:8400` | Unified OpenAI, Anthropic, and Gemini endpoint family. |
| [`fx`](docs/fx.md) | Vercel Labs fx | `127.0.0.1:18475` | Streaming inference and tool-result continuation. |
| [`xai`](docs/adapters-and-presets.md#6-xai-grok-preset-xai) | xAI Grok | `127.0.0.1:18476` | Native Grok routing with live search integration. |

---

## 📚 Documentation

| Resource | Description |
| :--- | :--- |
| [**Agent Native Setup Guide**](docs/agent-native.md) | Complete prompt cookbook and autonomous protocol for AI coding agents. |
| [**Overview**](docs/index.md) | Architectural deep-dive, security boundaries, and data flow. |
| [**Quickstart**](docs/quickstart.md) | 3-minute starter guide with subscription and API key login. |
| [**CLI Reference**](docs/cli-reference.md) | Complete reference for all subcommands, arguments, and flags. |
| [**Adapters & Presets**](docs/adapters-and-presets.md) | Presets for Cursor, Devin, Factory Droid, and Gateways. |
| [**Provider Login & Auth**](docs/provider-login.md) | Device OAuth, browser PKCE, and encrypted SQLite storage. |
| [**Management & Dashboard**](docs/management.md) | REST management API, request timeline explorer, and usage ledger. |
| [**Troubleshooting & Doctor**](docs/troubleshooting.md) | Diagnostic checks and preflight network verification. |
| [**Production Deployment**](docs/deployment.md) | Docker, docker-compose, and systemd units. |
| [**llms.txt**](llms.txt) | Curated agent-native project index. |

---

<div align="center">

**Built with precision by Coder Company**

[Report Issue](https://github.com/coder-company/pooler/issues) · [Discussions](https://github.com/coder-company/pooler/discussions) · [Documentation](docs/index.md)

</div>
