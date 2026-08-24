# Troubleshooting and diagnostics

This guide covers diagnostic tools, health checks, error codes, and resolution steps for Pooler installations.

## Diagnostic tools

### 1. Run local environment diagnostics with `doctor`

`pooler doctor` runs local read-only checks covering file permissions, store integrity, master key derivation, port availability, and configuration validity:

```sh
pooler doctor --config pooler.yaml
```

Example output:
```json
{
  "status": "ok",
  "checks": [
    {
      "name": "config.valid",
      "status": "passed",
      "detail": "configuration parsed and compiled successfully"
    },
    {
      "name": "store.sqlite_master_key",
      "status": "passed",
      "detail": "master key derived and encrypted store readable"
    },
    {
      "name": "listeners.ports_available",
      "status": "passed",
      "detail": "all configured listener ports are available"
    }
  ]
}
```

If any check fails, `pooler doctor` returns exit code `1` and details the failing check.

### 2. Verify upstream connectivity with `preflight`

`pooler preflight` tests DNS resolution, native-root TLS certificates, and provider base-endpoint reachability:

```sh
pooler --config pooler.yaml preflight
```

Preflight never sends inference requests and reports `inference_requests_sent: 0`.

---

## Common issues and solutions

### Port binding conflict (`Address already in use`)

- **Cause**: Another process or previous Pooler instance is bound to the configured port (for example, `8319`, `18477`, or `8400`).
- **Fix**: Check running processes on the port:
  ```sh
  lsof -i :8319
  ```
  Terminate the blocking process or update the `bind` address in `pooler.yaml`.

### Credential store key mismatch (`cannot decrypt store`)

- **Cause**: The master key supplied via `--credential-key-ref` does not match the key used when initializing `credentials.sqlite3`.
- **Fix**: Verify that the environment variable or file referenced by `--credential-key-ref` contains the exact 32-byte key generated during initialization:
  ```sh
  # If using file reference:
  pooler --config pooler.yaml --credential-key-ref file:/path/to/store.key doctor
  ```

### Insecure file permissions warning

- **Cause**: Secrets, configuration files, or the credential store have group-readable or world-readable permissions.
- **Fix**: Restrict permissions to owner-only:
  ```sh
  chmod 0700 /path/to/pooler-directory
  chmod 0600 /path/to/pooler-directory/*.key /path/to/pooler-directory/*.token
  ```

### Unsupported route or protocol error (`404 Not Found` or `400 Bad Request`)

- **Cause**: A client requested an endpoint or method that is not mapped by the active compiled routes.
- **Fix**: Inspect all compiled routes in match order:
  ```sh
  pooler --config pooler.yaml routes
  ```
  If the route is missing, check your route definitions or import the corresponding preset (such as `gateway`, `cursor`, `devin`, or `factory`).

---

## Generating a diagnostic export

For support and bug reports, export a redacted diagnostic bundle:

```sh
curl -H "Authorization: Bearer $POOLER_MANAGEMENT_TOKEN" \
  http://127.0.0.1:18477/export > pooler-diagnostic-export.json
```

The diagnostic export contains process status, compiler statistics, route metadata, and configuration generations. All secrets, credentials, authorization headers, prompts, and response bodies are strictly omitted.
