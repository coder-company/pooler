# Agent-native setup

Pooler is set up by an agent, not by hand. You paste one prompt into your coding agent, the agent asks you what you need, and it does the rest.

This page has two distinct things. Section 1 is the prompt **you** paste into an agent. Section 2 is the protocol the **agent** follows once it has that prompt. They are different documents with different audiences: do not paste section 2.

---

## 1. The prompt you paste into your agent

Paste this into Cursor, Devin, Claude Code, Codex, Factory Droid, or any coding agent:

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

---

## 2. The protocol the agent follows

An agent that receives the prompt above should work through these steps in order. Every command and path below is verified against the shipped binary.

### Step 1: Ask before acting

Do not create files, install binaries, or run network commands until the user has answered the five questions. Use a structured question tool when one is available so the user picks from options rather than typing free text.

Two answers change everything downstream, so resolve them first:

- **Which tools**, because each tool needs a different preset and port.
- **System-wide or per-user**, because it selects the install path and the configuration location.

### Step 2: Install the binary

System-wide is the default and needs root:

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | sudo bash
```

Per-user needs no root:

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash -s -- --user
```

The first installs `/usr/local/bin/pooler`; the second installs `~/.local/bin/pooler` and may require a `PATH` update. Confirm with `pooler --version` before continuing.

### Step 3: Know where the configuration lives

Pooler resolves its configuration in this order:

1. an explicit `--config PATH`;
2. `./pooler.yaml` in the current directory;
3. `$XDG_CONFIG_HOME/pooler/pooler.yaml`, normally `~/.config/pooler/pooler.yaml`.

For a per-user install, place the configuration at `~/.config/pooler/pooler.yaml`. Every bare command such as `pooler check`, `pooler serve`, and `pooler dashboard` then resolves it with no flags.

`pooler init` does **not** write to `~/.config/pooler`. It creates a new starter directory in the current working directory:

```sh
pooler init --output ./pooler-starter
```

That directory contains `pooler.yaml`, a generated `management.token`, a generated `store.key`, and an empty `provider.key`. The directory is mode `0700` and the files are `0600`. The command refuses to overwrite an existing destination. Use it to generate secrets and a validated starting point, then either pass `--config ./pooler-starter/pooler.yaml` explicitly or move the configuration to `~/.config/pooler/pooler.yaml`.

For a system service, install to the canonical layout instead. See step 7.

### Step 4: Write the configuration

Import one preset per tool the user named. Namespace each import with `as` and keep the default binds unless they collide.

```yaml
version: 2

imports:
  - preset: cursor
    as: cursor-adapter
    with:
      bind: 127.0.0.1:8333
      reasoning_effort: high
      model_prefix: gpt-

  - preset: gateway
    as: gateway
    with:
      bind: 127.0.0.1:8400

management:
  bind: 127.0.0.1:18477
  auth:
    secret: file:/absolute/path/to/management.token
```

Parameter names are validated strictly and differ per preset. Use the table in [adapters and presets](adapters-and-presets.md#preset-reference). The most common mistake is passing `upstream_url` to the `xai` preset, which takes `rest_url`.

Validate after every edit:

```sh
pooler check
```

### Step 5: Sign the user in

Which login methods exist depends on the provider. Read the shipped matrix rather than assuming:

```sh
pooler auth providers
```

The current support matrix is:

| Provider | Aliases | API key | Browser PKCE | Device code |
| :--- | :--- | :--- | :--- | :--- |
| OpenAI | `codex` | Supported | Supported | Supported |
| Google | `gemini` | Supported | Supported | Not supported |
| Anthropic | `claude` | Supported | Not supported | Not supported |
| xAI | `grok` | Supported | Not supported | Not supported |
| Kimi | `moonshot` | Supported | Not supported | Needs operator registration |
| Palantir AIP | `foundry` | Not supported | Needs operator registration | Not supported |

Do not offer a ChatGPT-style OAuth login for Anthropic or xAI. Those providers use API keys.

For a ChatGPT or Codex subscription, use the device flow:

```sh
pooler --credential-key-ref file:/absolute/path/to/store.key \
  auth login openai --method device-code
```

Show the verification URL and the short user code to the user, wait for them to authorize, then confirm:

```sh
pooler --credential-key-ref file:/absolute/path/to/store.key auth status openai
```

If the user already signed in with the Codex CLI, import those credentials instead of starting a new flow:

```sh
pooler --credential-key-ref file:/absolute/path/to/store.key \
  auth import codex-account --profile codex --from-file ~/.codex/credentials.json
```

For Google Gemini, use the loopback browser flow. It listens on `http://localhost:1455/auth/callback` by default:

```sh
pooler --credential-key-ref file:/absolute/path/to/store.key \
  auth login google --method oauth
```

For API-key providers, ask the user to export the variable in their shell profile and reference it from the configuration. Pooler never accepts an API key as a command-line value.

```sh
export ANTHROPIC_API_KEY="..."
export XAI_API_KEY="..."
```

```yaml
upstreams:
  anthropic:
    known_provider: anthropic
    auth:
      secret: env:ANTHROPIC_API_KEY
```

### Step 6: Verify, then start

```sh
pooler check
pooler preflight
```

`preflight` probes DNS, TLS, endpoint reachability, and configured discovery. It sends no inference request and reports `inference_requests_sent: 0`, so it costs nothing. Treat any failing check as a stop condition and report it rather than starting the runtime.

Then start the runtime and open the dashboard:

```sh
pooler serve
pooler dashboard
```

`pooler dashboard` derives the URL from the loopback management bind and prints it. The management bearer token is entered in the browser and is never placed in the URL. Use `--no-open` to print without launching a browser.

If the user needs a terminal view instead of a browser:

```sh
pooler tui --token-ref file:/absolute/path/to/management.token
```

### Step 7: Optional hardened system service

For a shared machine or a server, install the canonical systemd service from a release archive rather than running `pooler serve` by hand:

```sh
scripts/install-system-pooler.sh --dry-run
sudo scripts/install-system-pooler.sh --promote
```

The installer validates its inputs before copying anything and is inert with respect to systemd unless `--promote` is passed. It requires root and a pre-existing `pooler` user and group. Its canonical layout is fixed:

| Path | Contents |
| :--- | :--- |
| `/usr/local/bin/pooler` | Binary |
| `/etc/pooler/pooler.yaml` | Configuration |
| `/etc/pooler/store.key` | Credential-store key, generated when absent |
| `/etc/pooler/management.key` | Management bearer, generated when absent |
| `/var/lib/pooler/credentials.sqlite3` | Encrypted credential store |
| `/etc/systemd/system/pooler.service` | Unit |
| `/var/backups/pooler` | Timestamped backups of replaced files |

The service binds inference on `127.0.0.1:18400` and management on `127.0.0.1:18401`. These differ from the `pooler init` starter, which uses `18477` for management. The installer rejects a configuration that does not bind those two ports or that references anything other than `file:/etc/pooler/management.key`.

### Step 8: Report the exact connection settings

Finish by telling the user what to paste where, for the tools they actually named:

| Tool | Setting |
| :--- | :--- |
| Cursor | OpenAI base URL `http://127.0.0.1:8333` |
| Devin | Service endpoint `http://127.0.0.1:18473` |
| Factory Droid | Base URL `http://127.0.0.1:18474` |
| Vercel fx | Base URL `http://127.0.0.1:18475` |
| xAI Grok | Base URL `http://127.0.0.1:18476` |
| OpenAI SDKs | `OPENAI_BASE_URL="http://127.0.0.1:8400/v1"` |
| Anthropic SDKs | `ANTHROPIC_BASE_URL="http://127.0.0.1:8400"` |
| Gemini SDKs | Base URL `http://127.0.0.1:8400` |

Some clients require a non-empty API-key field even when they do not need one. Use a non-secret placeholder; upstream credentials are selected server-side.

---

## 3. Follow-up task prompts

Once Pooler runs, these prompts handle common changes. Each is written for the user to paste.

### Pool several accounts with failover

```text
Add a second account to my Pooler configuration and pool it with the first so
requests fail over automatically when one account hits a rate limit. Read the
account, account_pools, and policies sections of
https://raw.githubusercontent.com/coder-company/pooler/main/schema/pooler.schema.json
so you use real field names, then validate with `pooler check` before you tell
me it works.
```

### Switch which account is active

```text
Show me my configured Pooler accounts with `pooler auth status`, then switch the
active one to the account I pick using `pooler auth switch`, and confirm the
change.
```

### Investigate slow or failing requests

```text
My requests through Pooler are slow. Read
https://raw.githubusercontent.com/coder-company/pooler/main/docs/management.md,
then use the management API on 127.0.0.1:18477 with the bearer token from my
management.token file to summarize recent request latency, time-to-first-token,
retries, and any quota cooldowns. Do not send any inference requests.
```

### Diagnose a broken setup

```text
Pooler is not working. Run `pooler doctor` and `pooler preflight`, read
https://raw.githubusercontent.com/coder-company/pooler/main/docs/troubleshooting.md,
and fix what you can. Report anything you cannot fix safely.
```

### Migrate from CLIProxyAPI

```text
I have a CLIProxyAPI configuration at <PATH>. Run
`pooler migrate cliproxy <PATH> --dry-run` first and show me the redacted
proposal. If it looks right, write the result to a new file and validate it with
`pooler check`. Do not modify my original file.
```

---

## Rules for agents

Apply these to every task on this page.

1. Ask first. Do not guess which tools, accounts, or models the user wants.
2. Never write a literal API key, token, OAuth client secret, or bearer into YAML, a shell command, or a log. Use `env:`, `file:`, or `keyring:` references.
3. Run `pooler check` after every configuration edit, and `pooler preflight` before claiming the setup works. Treat a failure as a stop condition.
4. Never overwrite an existing configuration or starter directory. Write to a new path and tell the user what changed.
5. Read `pooler auth providers` before offering a login method. Do not invent OAuth support for a provider that only accepts API keys.
6. Confirm the listening ports with `pooler routes` or `pooler endpoint-inventory` before reporting a base URL.
