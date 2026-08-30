# CLI reference

Every command, argument, and flag shipped by the `pooler` binary. Verify against your build with `pooler --help` and `pooler <command> --help`.

## Global options

These apply to every subcommand.

| Option | Description |
| :--- | :--- |
| `-c`, `--config <PATH>` | Configuration file to load. When omitted, Pooler uses an existing `./pooler.yaml`; otherwise it discovers `$XDG_CONFIG_HOME/pooler/pooler.yaml`, normally `~/.config/pooler/pooler.yaml`. |
| `--credential-store <PATH>` | Owner-private SQLite credential store. When omitted, Pooler uses the platform state directory or `POOLER_CREDENTIAL_STORE`. |
| `--credential-key-ref <REF>` | Secret reference used to derive the encrypted credential-store key. Literal values are rejected; use `env:`, `file:`, or `keyring:`. |
| `--watch` | Poll the root configuration and imported files for debounced changes while serving. On Unix, `SIGHUP` always forces an immediate reload. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

## Secret references

Wherever a secret is required, Pooler accepts only a reference, never a literal:

| Form | Meaning |
| :--- | :--- |
| `env:NAME` | Read from the environment variable `NAME`. |
| `file:/absolute/path` | Read from an owner-private file, mode `0600`. |
| `keyring:service/account` | Read from the OS keyring. |

---

## Setup and inspection

### `pooler init`

Create a compiler-validated, owner-private starter deployment.

```sh
pooler init [--output <DIR>] [--json]
```

| Argument | Description |
| :--- | :--- |
| `--output <DIR>` | Directory to create. Default `pooler-starter`. The command refuses an existing destination and removes a partially created one on failure. |
| `--json` | Emit the redacted bootstrap report as JSON. |

The directory contains `pooler.yaml`, a generated `management.token`, a generated `store.key`, and an empty `provider.key`. The directory is mode `0700` and files are `0600`. The YAML holds only absolute `file:` references and never embeds a generated value.

This command does not write to `~/.config/pooler`. Move the generated `pooler.yaml` there yourself if you want flag-free commands.

### `pooler check`

Parse and validate the configuration, including imports, presets, and the compiled route plan. Starts nothing.

```sh
pooler check [--config <PATH>]
```

### `pooler config`

```sh
pooler config render
pooler config schema [--output <PATH>]
pooler config recovery
```

| Subcommand | Description |
| :--- | :--- |
| `render` | Print the source after validating it, with imports and presets expanded. Secrets are not resolved. |
| `schema` | Print the deterministic source-configuration JSON Schema, or write it to `--output <PATH>`. |
| `recovery` | Inspect and safely recover a blocked managed-configuration transaction. |

### `pooler routes`

List compiled route IDs in match order. Use `pooler endpoint-inventory` for listener, method, path, protocol, and target details.

```sh
pooler routes [--config <PATH>]
```

### `pooler models`

List configured public models.

```sh
pooler models [--json]
```

`--json` emits merged targets, source policy, and provenance.

### `pooler providers`

List providers this build ships an endpoint for. This is the provider catalog, not the login matrix; for login support use `pooler auth providers`.

```sh
pooler providers [--search <TEXT>] [--json]
```

### `pooler endpoint-inventory`

Print every configured listener and management endpoint without using a named client profile. Output is JSON for scripting; `--json` is a compatibility alias and produces identical output.

```sh
pooler endpoint-inventory [--json]
```

### `pooler catalog`

Maintain the vendored per-model request-facts snapshot.

```sh
pooler catalog refresh
pooler catalog facts
```

| Subcommand | Description |
| :--- | :--- |
| `refresh` | Regenerate the vendored request-facts snapshot from the upstream catalog. |
| `facts` | Print the request facts compiled into this build. |

---

## Running

### `pooler serve`

Start the proxy runtime and, when configured, the management listener.

```sh
pooler serve [--config <PATH>] [--credential-key-ref <REF>] [--watch]
```

Listener and management bind changes require a process restart. Other configuration changes can be applied by reload.

### `pooler dashboard`

Open or print the authenticated management dashboard URL.

```sh
pooler dashboard [--url <URL>] [--no-open]
```

| Argument | Description |
| :--- | :--- |
| `--no-open` | Print the URL without launching a browser. |
| `--url <URL>` | An explicit trusted remote dashboard URL. Must be absolute HTTPS with no user information, query, or fragment. |

Without `--url`, the URL is derived from the loopback management bind. The bearer token is entered in the browser and never placed in the URL. A Unix-socket management bind cannot be opened in a browser; use `pooler tui`.

### `pooler tui`

Open a thin terminal view backed entirely by the management API.

```sh
pooler tui --token-ref <REF> [--endpoint <URL>] [--once] [--interval-secs <N>]
```

| Argument | Description |
| :--- | :--- |
| `--token-ref <REF>` | Required. Management bearer reference: `env:`, owner-private `file:`, or `keyring:`. |
| `--endpoint <URL>` | Management listener origin. Default `http://127.0.0.1:18477`. Cleartext HTTP is accepted only on loopback. |
| `--once` | Render one snapshot and exit. |
| `--interval-secs <N>` | Refresh interval for the live view. Default `5`. |

---

## Diagnostics

### `pooler doctor`

Run local read-only diagnostics over configuration, listener ports, file permissions, credential-store integrity, and extensions. Emits one redacted JSON report and exits non-zero when any check fails.

```sh
pooler doctor [--config <PATH>]
```

### `pooler preflight`

Probe DNS, TLS, authentication, discovery, and endpoint reachability without inference.

```sh
pooler preflight [--config <PATH>]
```

Sends no inference request and reports `inference_requests_sent: 0`. Provider-specific authentication placement and quota endpoints are not probed, so success does not claim quota availability or model correctness.

---

## Credentials

All `auth` subcommands take the account or provider as a positional argument, not as a flag.

### `pooler auth providers`

Show built-in provider login support and safe API-key guidance.

```sh
pooler auth providers [PROFILE]
```

Profile names and aliases are case-insensitive. Run this before choosing a login method; support is decided by the provider, not by Pooler.

| Provider | Aliases | API key | Browser PKCE | Device code |
| :--- | :--- | :---: | :---: | :---: |
| OpenAI | `codex` | Yes | Yes | Yes |
| Google | `gemini` | Yes | Yes | No |
| Anthropic | `claude` | Yes | No | No |
| xAI | `grok` | Yes | No | No |
| Kimi | `moonshot` | Yes | No | Needs operator registration |
| Palantir AIP | `foundry` | No | Needs operator registration | No |

### `pooler auth login`

Log in with a provider profile or a configured custom OAuth provider.

```sh
pooler auth login <PROVIDER> [--account <ID>] [--profile <ID>] [--method <METHOD>] [--callback <URL>]
```

| Argument | Description |
| :--- | :--- |
| `<PROVIDER>` | Configured OAuth upstream or provider ID. |
| `--account <ID>` | Configured account ID. Required when the provider has more than one OAuth account. |
| `--profile <ID>` | Built-in provider profile ID or alias. Inferred from the provider ID by default. |
| `--method <METHOD>` | `oauth` (authorization code with state and S256 PKCE, the default), `device-code`, or `api-key` for guidance only. |
| `--callback <URL>` | Loopback callback URI. Default `http://localhost:1455/auth/callback`. Must be HTTP on `localhost` or an IP loopback address with no query, fragment, or user information. |

An API key is never accepted as a command-line value. Built-in profiles enforce provider DNS allowlists that endpoint overrides cannot bypass; replacing endpoints for an unprofiled custom provider additionally requires `--dangerously-allow-custom-oauth-endpoints`. See [provider login](provider-login.md) for endpoint overrides and `--request-encoding`.

### `pooler auth import`

Import an owner-private OpenAI Codex subscription credential file.

```sh
pooler auth import <ACCOUNT> --profile <openai|codex> --from-file <PATH>
```

### `pooler auth status`

Show redacted local credential metadata.

```sh
pooler auth status [PROVIDER]
```

### `pooler auth refresh`, `revoke`, `enable`, `disable`, `switch`

```sh
pooler auth refresh <ACCOUNT>
pooler auth revoke <ACCOUNT>
pooler auth enable <ACCOUNT>
pooler auth disable <ACCOUNT>
pooler auth switch <ACCOUNT>
```

`refresh` and `revoke` accept an account ID, or a provider that has exactly one account. `switch` selects one account and disables its siblings for the same provider. `revoke` removes only Pooler's local credential payload and disables the account; it does not claim provider-side revocation unless the provider flow performs it. The CLI lifecycle commands update the durable store out of process. While `pooler serve` is running, use the authenticated management account endpoints instead so the mutation is published to every live runtime generation immediately; a direct CLI enable, disable, or switch is otherwise observed after the server restarts.

---

## Migration and fixtures

### `pooler migrate cliproxy`

Convert a supported legacy CLIProxyAPI configuration without retaining secret values.

```sh
pooler migrate cliproxy <INPUT> [--dry-run] [--output <PATH>]
```

| Argument | Description |
| :--- | :--- |
| `--dry-run` | Report the redacted proposal without writing any file. |
| `--output <PATH>` | Destination for the new owner-private configuration. Must not already exist. |

The parser is restricted to the supported legacy shape and a 1 MiB input. Legacy API keys and management secrets are never retained or printed. The source file is never modified.

### `pooler fixture`

Inspect and replay sanitized compatibility fixtures.

```sh
pooler fixture replay <PATH> [--actual <PATH>]
pooler fixture capture <INPUT> <OUTPUT> [--include-bodies] [--max-body-bytes <N>]
pooler fixture report [--manifest <PATH>] [--format markdown|json] [--output <PATH>]
```

`capture` omits bodies by default; retaining bounded, recursively redacted JSON bodies requires `--include-bodies`.
