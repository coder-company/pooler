# Support

## Setting Pooler up

Start with the [agent-native setup](docs/agent-native.md), which is the intended path: you paste one prompt into a coding agent and it asks what you need. If you would rather do it by hand, use the [quickstart](docs/quickstart.md).

## Something is not working

Run the two diagnostic commands first. Both are read-only and neither sends a billable request:

```sh
pooler doctor      # configuration, ports, file permissions, credential store
pooler preflight   # DNS, TLS, endpoint reachability
```

Then check [troubleshooting](docs/troubleshooting.md). It covers the failures people actually hit: configuration not being found, strict schema rejections, port conflicts, credential-store key mismatches, unsupported login methods, and the dashboard refusing to open.

Two things catch almost everyone:

- **`pooler init` does not create `~/.config/pooler/pooler.yaml`.** It creates a starter directory in the current directory. Bare commands will not find it until you move the file or pass `--config`.
- **A provider may not support the login method you want.** Anthropic and xAI accept API keys only. Run `pooler auth providers` to see the real matrix.

## Where to ask

| I want to | Go here |
| :--- | :--- |
| Ask how to do something | [Discussions](https://github.com/coder-company/pooler/discussions) |
| Report a bug | [New issue](https://github.com/coder-company/pooler/issues/new/choose) |
| Report a vulnerability | [Private advisory](https://github.com/coder-company/pooler/security/advisories/new) or [c@coder.company](mailto:c@coder.company), never a public issue |
| Propose a feature | [New issue](https://github.com/coder-company/pooler/issues/new/choose) |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the version from `pooler --version`, your platform, how you installed Pooler, and the commands you ran. Attach `pooler doctor` output.

**Redact every secret.** Keep the reference form, such as `env:OPENAI_API_KEY`, and remove values. `pooler config render` prints an expanded configuration without resolving secrets. A diagnostic export is metadata-only by design, but review it before attaching it anyway:

```sh
curl -H "Authorization: Bearer $(cat /path/to/management.token)" \
  http://127.0.0.1:18477/export > pooler-diagnostic-export.json
```

## Reference

| Guide | Covers |
| :--- | :--- |
| [Overview](docs/index.md) | How Pooler fits together, default ports, provider support |
| [CLI reference](docs/cli-reference.md) | Every command and flag |
| [Adapters and presets](docs/adapters-and-presets.md) | Presets, their parameters, and their ports |
| [Provider login](docs/provider-login.md) | Device and browser OAuth, API-key guidance |
| [Provider catalog](docs/provider-catalog.md) | Known providers and custom endpoints |
| [Management](docs/management.md) | Management API, request explorer, usage ledger |
| [Deployment](docs/deployment.md) | Container and systemd deployment |

## Support expectations

Pooler is pre-1.0 and maintained by Coder Company. Issues and discussions are answered on a best-effort basis, and there is no service-level commitment. Security reports are prioritized; see [SECURITY.md](SECURITY.md) for response targets.
