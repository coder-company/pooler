# Pooler

Pooler is a **system-wide AI protocol runtime and pooling proxy** by Coder Company. It connects all your AI coding tools (**Cursor**, **Devin**, **Factory Droid**, **Claude Code**, and terminal SDKs) across all your projects to your **ChatGPT / Codex subscriptions** and **model provider APIs** (OpenAI, Anthropic Claude, Google Gemini, xAI Grok, custom providers).

```
+-------------------------------------------------------------------------------+
|  Your Machine's Coding Tools & Agents (All Projects & Workspaces)             |
|  Cursor (8333) | Devin (18473) | Factory Droid (18474) | SDKs / CLI (8400)    |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|  Pooler System-Wide Daemon (Local Background Process)                         |
|  - System configuration at ~/.config/pooler/pooler.yaml                       |
|  - Translates protocols (ConnectRPC, Factory, OpenAI, Claude, Gemini)         |
|  - Pools multiple subscriptions & API keys with automatic failover            |
|  - Stores credentials in encrypted local SQLite                               |
|  - Serves live dashboard on http://127.0.0.1:18477 via `pooler dashboard`     |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|  Subscriptions & AI Providers                                                 |
|  ChatGPT / Codex Subscriptions | Claude | Gemini | xAI Grok | Custom          |
+-------------------------------------------------------------------------------+
```

---

## Why use Pooler?

1. **System-wide local endpoint**: Set up your tools once. All your repositories, workspaces, and CLI tools route through Pooler without repeating project-level setup.
2. **Account pooling and automatic failover**: Connect multiple subscriptions or API keys. When one hits a rate limit or hourly quota, Pooler switches to the next available account.
3. **Safe authentication**: Log in using official provider OAuth (like OpenAI Codex device login or Google OAuth). Tokens stay encrypted in your local SQLite store (`AES-GCM`).
4. **Agent-native setup**: Configure integrations by giving a single prompt to your coding agent (Cursor, Devin, Claude Code) to configure your machine.
5. **Instant dashboard**: Run `pooler dashboard` to view live requests, latency, time-to-first-token (TTFT), token counts, and cost estimates on `http://127.0.0.1:18477`.

---

## How it works in 3 steps

### Step 1: Install & initialize system-wide
```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash
pooler init
```

### Step 2: Connect your subscription or API key
```sh
pooler auth login openai --method device-code
```

### Step 3: Start serving and open dashboard
```sh
pooler serve &
pooler dashboard
```

---

## Documentation guides

| Guide | What you will learn |
| :--- | :--- |
| [Agent Native Guide](agent-native.md) | Ready-made prompts for Cursor, Devin, and coding agents to configure your machine. |
| [Quickstart](quickstart.md) | System-wide setup and quickstart in under 3 minutes. |
| [Adapters & Presets](adapters-and-presets.md) | Pre-built configurations for Cursor, Devin, Factory Droid, and multi-provider gateways. |
| [CLI Reference](cli-reference.md) | Complete list of all commands, options, and flags. |
| [Provider Login & Auth](provider-login.md) | How to log into OpenAI, Claude, Google Gemini, and manage accounts. |
| [Management & Dashboard](management.md) | How to use the local web dashboard, live request explorer, and usage ledger. |
| [Troubleshooting](troubleshooting.md) | Run `pooler doctor` and `pooler preflight` to fix common setup issues. |
| [Production Deployment](deployment.md) | Run Pooler with Docker, docker-compose, or systemd. |
