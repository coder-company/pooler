# Quickstart

Pooler runs as a **system-wide daemon** on your machine. Once started, all your coding tools and projects talk to the same local endpoint.

## 1. Install Pooler system-wide

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash
```

---

## 2. Initialize configuration

Initialize your user-level configuration at `~/.config/pooler/pooler.yaml`:

```sh
pooler init
```

---

## 3. Connect your subscriptions or API keys

### ChatGPT / Codex Subscription (OAuth Device Flow)
```sh
pooler auth login openai --method device-code
```
*Open the verification URL in your browser, enter the one-time user code, and authorize.*

### Google Gemini (Browser PKCE)
```sh
pooler auth login google --method oauth
```

### API Keys (Claude, OpenAI, xAI)
Export your keys in your shell profile (`~/.bashrc` or `~/.zshrc`):
```sh
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

---

## 4. Validate and start

```sh
# Validate configuration & network connectivity
pooler check
pooler preflight

# Start the system daemon
pooler serve &

# Open the management dashboard
pooler dashboard
```

---

## 5. Connect your coding tools globally

Configure your coding tools once to point to Pooler:

- **Cursor IDE**: Set OpenAI Base URL to `http://127.0.0.1:8333` in Settings → Models.
- **Devin**: Point endpoint to `http://127.0.0.1:18473`.
- **Factory Droid**: Point AI Base URL to `http://127.0.0.1:18474`.
- **Claude Code / AI SDKs**: Add to your shell profile:
  ```sh
  export OPENAI_BASE_URL="http://127.0.0.1:8400/v1"
  export ANTHROPIC_BASE_URL="http://127.0.0.1:8400"
  ```
