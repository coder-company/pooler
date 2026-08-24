# Troubleshooting

Start with the two diagnostic commands. Both are read-only and neither sends a billable request.

```sh
pooler doctor
pooler preflight
```

`doctor` checks the local installation: configuration compilation, listener port availability, file permissions, credential-store integrity, and extensions. It emits one redacted JSON report and exits non-zero if any check fails.

`preflight` checks the network: DNS resolution, native-root TLS, base-endpoint reachability, and configured discovery. It reports `inference_requests_sent: 0`. Success does not claim quota availability or model correctness.

---

## Configuration is not found

```
failed to read configuration `/home/you/.config/pooler/pooler.yaml`: file does not exist
```

Pooler resolves configuration in this order: an explicit `--config PATH`, then `./pooler.yaml`, then `$XDG_CONFIG_HOME/pooler/pooler.yaml`.

`pooler init` does not create the third path. It creates a starter directory in the current directory, so bare commands will not find it. Either pass the path explicitly or move the file:

```sh
mkdir -p ~/.config/pooler
mv ./pooler-starter/pooler.yaml ~/.config/pooler/pooler.yaml
```

## An unknown field is rejected

```
policies.my-policy.selection: unknown field `accounts`, expected one of `strategy`, `session_affinity`, `affinity`
```

The configuration schema is strict, so a misplaced or misspelled key fails instead of being ignored. The error names the section, the offending key, and the accepted alternatives.

Accounts belong in `accounts` and `account_pools`, not inside `policies.<name>.selection`. To see the authoritative field list for any section:

```sh
pooler config schema
```

## An unknown preset parameter is rejected

```
invalid configuration at pooler.yaml:1:1 ($): unknown preset parameter `upstream_url`
```

Preset parameters are validated per preset and are not interchangeable. In particular, the `xai` preset takes `rest_url`, not `upstream_url`. See the [preset reference](adapters-and-presets.md#preset-reference) for the exact list each preset accepts.

## A port is already in use

```
Address already in use
```

Find the process holding the port and either stop it or change the `bind` in your configuration:

```sh
lsof -i :8333
```

Two presets share a default: `xai` and `media` both bind `127.0.0.1:18476`. If you import both, change one `bind`.

Confirm what Pooler intends to bind before starting it:

```sh
pooler routes
pooler endpoint-inventory
```

## The credential store cannot be decrypted

The `--credential-key-ref` you passed does not derive the key that encrypted `credentials.sqlite3`. The reference must resolve to the same secret used when the store was created, for example the `store.key` written by `pooler init`:

```sh
pooler --credential-key-ref file:/absolute/path/to/store.key doctor
```

Literal values are rejected. Use `env:`, `file:`, or `keyring:`.

## A login method is not supported

```
Anthropic does not support OAuth device-code login.
```

Login support is decided by the provider. Anthropic and xAI accept API keys only; Google supports browser PKCE but not device code; Kimi and Palantir AIP need an operator-owned client registration that Pooler will not invent.

Check what is actually available before retrying:

```sh
pooler auth providers
pooler auth providers gemini
```

## The dashboard will not open

`pooler dashboard` needs a `management` section with a loopback TCP bind. Common causes:

- **Management is disabled.** Add a `management` block with a `bind` and an `auth.secret` reference.
- **The bind is not loopback.** Remote dashboards require an explicit trusted HTTPS `--url`.
- **The bind is a Unix socket.** A browser cannot open it; use `pooler tui --token-ref file:/path/to/management.token`.

The bearer token is entered in the browser, never in the URL. `--no-open` prints the URL without launching a browser.

## Permissions are too open

Pooler treats credential material as owner-private. Restore the expected modes:

```sh
chmod 0700 /path/to/pooler-directory
chmod 0600 /path/to/pooler-directory/*.key /path/to/pooler-directory/*.token
```

## A request returns 404 or 400

The client asked for an endpoint or method no compiled route matches. List the routes in match order and compare:

```sh
pooler routes
```

If the route is missing, import the preset for that client rather than hand-authoring one. See [adapters and presets](adapters-and-presets.md).

A `400` can also mean a route rejected a request it could not represent faithfully. The `devin` preset uses `loss_policy: reject` deliberately, so an unrepresentable request fails instead of degrading silently.

---

## Collecting a diagnostic export

For a bug report, export the redacted diagnostic bundle:

```sh
curl -H "Authorization: Bearer $(cat /path/to/management.token)" \
  http://127.0.0.1:18477/export > pooler-diagnostic-export.json
```

The export contains process status, compiled route metadata, and configuration generations. Secrets, credentials, authorization headers, prompts, and response bodies are never included. It is a diagnostic bundle, not a credential backup, and cannot restore tokens.
