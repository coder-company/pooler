# CLI reference

Pooler provides a command-line interface for configuration validation, server execution, provider authentication, migration, diagnostics, and operational controls.

## Global options

| Option | Environment variable | Description |
| :--- | :--- | :--- |
| `-c, --config <PATH>` | `POOLER_CONFIG` | Path to the YAML configuration file. Defaults to `./pooler.yaml` or `$XDG_CONFIG_HOME/pooler/pooler.yaml`. |
| `--credential-store <PATH>` | `POOLER_CREDENTIAL_STORE` | Path to the SQLite credential store database. Defaults to the platform state directory. |
| `--credential-key-ref <REF>` | `POOLER_CREDENTIAL_KEY_REF` | Secret reference used to derive the AES-GCM credential encryption key (`env:VAR`, `file:/path`, or `keyring:service/account`). Literal values are rejected. |
| `--watch` | - | Polls root configuration and imported files for debounced changes while serving. |
| `-h, --help` | - | Prints help information. |
| `-V, --version` | - | Prints version information. |

---

## Subcommands

### `pooler init`
Creates an owner-private starter deployment in a new directory with restricted permissions (`0700` directory, `0600` files).

```sh
pooler init [--output <DIR>] [--json]
```

- `--output <DIR>`: Output directory name (default: `pooler-starter`). Fails if the destination already exists.
- `--json`: Emits the bootstrap creation report as structured JSON.

### `pooler check`
Parses and validates the configuration file, route definitions, imports, presets, and schema without starting the server.

```sh
pooler check [--config <PATH>]
```

### `pooler serve`
Starts the proxy runtime, route listeners, and optional management API listener.

```sh
pooler serve [--config <PATH>] [--watch] [--credential-key-ref <REF>]
```

### `pooler doctor`
Runs local read-only diagnostics on configuration, ports, file permissions, store integrity, and crypto setup.

```sh
pooler doctor [--config <PATH>]
```

Returns exit code `0` on success, or non-zero with a JSON failure report detailing failing checks.

### `pooler preflight`
Probes upstream DNS resolution, native-root TLS handshakes, provider base endpoint reachability, and catalog discovery.

```sh
pooler preflight [--config <PATH>]
```

Preflight never sends billable inference requests (`inference_requests_sent: 0`).

### `pooler dashboard`
Prints or opens the authenticated management dashboard URL in your browser.

```sh
pooler dashboard [--config <PATH>] [--url <URL>] [--no-open]
```

- `--no-open`: Prints the dashboard URL without opening the system browser.
- `--url <URL>`: Specifies an explicit remote HTTPS dashboard origin.

### `pooler tui`
Opens a lightweight terminal user interface backed by the management API.

```sh
pooler tui --token-ref <REF> [--endpoint <URL>] [--once] [--interval-secs <SECS>]
```

- `--token-ref <REF>`: Reference to management bearer token (`env:VAR`, `file:/path`, or `keyring:svc/acct`). Required.
- `--endpoint <URL>`: Management listener origin (default: `http://127.0.0.1:18477`).
- `--once`: Renders a single snapshot and exits.
- `--interval-secs <SECS>`: Refresh interval in seconds for live view (default: `5`).

### `pooler routes`
Lists all compiled routes in match precedence order, displaying listening endpoints, HTTP methods, paths, and target upstreams.

```sh
pooler routes [--config <PATH>]
```

### `pooler models`
Lists all configured public models, merged target upstreams, source policy, and catalog provenance.

```sh
pooler models [--config <PATH>] [--json]
```

- `--json`: Emits the merged models catalog as JSON.

### `pooler providers`
Lists built-in provider login profiles, aliases, and endpoint guidance.

```sh
pooler providers [--search <QUERY>] [--json]
```

- `--search <QUERY>`: Filters providers matching the specified ID or name.
- `--json`: Emits the provider table as JSON.

### `pooler config`
Inspects and renders configuration files.

```sh
pooler config render [--config <PATH>]
```

- `render`: Expands all imports, presets, and defaults into a single normalized YAML document without resolving secrets.

### `pooler auth`
Manages provider OAuth tokens and credential states stored in the encrypted SQLite database.

```sh
pooler auth <SUBCOMMAND>
```

#### `pooler auth login`
Initiates an OAuth login flow for a provider profile.

```sh
pooler auth login <PROVIDER> \
  [--account <ID>] \
  [--profile <PROFILE>] \
  [--method oauth|device-code] \
  [--callback <URL>]
```

- `<PROVIDER>`: Upstream or provider identifier.
- `--account <ID>`: Account identifier (required if multiple accounts are configured for the provider).
- `--profile <PROFILE>`: Built-in profile identifier (such as `openai`, `codex`, `gemini`, `anthropic`, `xai`, `kimi`).
- `--method <METHOD>`: Authentication mechanism: `oauth` (browser PKCE loopback) or `device-code` (CLI device flow). Default: `oauth`.
- `--callback <URL>`: Loopback callback URI (default: `http://127.0.0.1:14555/oauth/callback`).

#### `pooler auth status`
Displays redacted credential metadata, token validity, and expiration times for stored accounts.

```sh
pooler auth status [--provider <ID>]
```

#### `pooler auth refresh`
Forces a token refresh for a configured OAuth account.

```sh
pooler auth refresh <ACCOUNT_OR_PROVIDER>
```

#### `pooler auth revoke`
Revokes credentials and removes local stored tokens for an account.

```sh
pooler auth revoke <ACCOUNT_OR_PROVIDER>
```

#### `pooler auth switch`
Enables the specified account for selection while disabling sibling accounts for the same provider.

```sh
pooler auth switch --account <ID>
```

#### `pooler auth enable` / `pooler auth disable`
Enables or disables an account from route selection pools.

```sh
pooler auth enable <ACCOUNT>
pooler auth disable <ACCOUNT>
```

#### `pooler auth import`
Imports an owner-private OpenAI Codex subscription credential JSON file into the encrypted store.

```sh
pooler auth import <ACCOUNT> --profile <openai|codex> --from-file <PATH>
```

### `pooler migrate`
Converts legacy configuration files to validated Pooler configuration files.

```sh
pooler migrate cliproxy <INPUT_YAML> [--dry-run] [--output <OUTPUT_YAML>]
```

- `--dry-run`: Emits the redacted migration proposal without writing files.
- `--output <OUTPUT_YAML>`: Path to write the new owner-private Pooler configuration.

### `pooler fixture`
Replays and captures test fixtures for protocol compatibility verification.

```sh
pooler fixture replay <PATH> [--actual <PATH>]
pooler fixture capture <INPUT> <OUTPUT> [--include-bodies] [--max-body-bytes <BYTES>]
pooler fixture report [--manifest <PATH>] [--format markdown|json] [--output <PATH>]
```

### `pooler catalog`
Maintains and inspects vendored model request facts.

```sh
pooler catalog list
pooler catalog check
```

### `pooler endpoint-inventory`
Prints every configured listener and management endpoint in JSON format for scripting.

```sh
pooler endpoint-inventory [--config <PATH>] [--json]
```
