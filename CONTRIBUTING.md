# Contributing to Pooler

Thanks for helping. This project has a strong bias toward *provable* behavior: a change is finished when the code, the tests, and the documentation agree with each other.

## Ground rules

Pooler sits between a developer's tools and their paid provider accounts, and it holds their credentials. Three consequences shape every contribution:

1. **Never claim compatibility you have not proven.** Unsupported protocol behavior must be rejected, not silently advertised or discarded. If Pooler cannot faithfully represent a request, the route fails.
2. **Never widen the credential surface.** Secrets are referenced, never inlined. An API key is never accepted as a command-line argument, written to a log, or included in an export.
3. **Never document behavior the binary does not have.** Documentation is checked in CI against the shipped binary. See [documentation](#documentation).

## Getting set up

You need the pinned Rust toolchain in `rust-toolchain.toml` and Python 3.12 for the check scripts.

```sh
git clone https://github.com/coder-company/pooler.git
cd pooler
cargo build -p pooler-cli --bin pooler
```

Validate an example configuration to confirm the build works:

```sh
cargo run -p pooler-cli -- check --config config/pooler.example.yaml
```

## Repository layout

| Path | Contents |
| :--- | :--- |
| `crates/pooler-cli` | Command-line interface and the `pooler` binary |
| `crates/pooler-config` | Source schema, preset expansion, and the configuration compiler |
| `crates/pooler-core` | Shared domain types |
| `crates/pooler-http`, `pooler-server` | Proxy runtime, management API, and dashboard |
| `crates/pooler-auth`, `pooler-store` | OAuth mechanics and the encrypted credential store |
| `crates/pooler-policy` | Account selection, retry, and quota policy |
| `crates/pooler-protocol` | Wire codecs and semantic conversion |
| `crates/adapter-*` | Per-client and per-provider adapters |
| `presets/` | Built-in preset sources, embedded at compile time |
| `fixtures/` | Sanitized compatibility fixtures and their manifest |
| `docs/` | Documentation published by Mintlify |
| `scripts/` | Check, release, and verification tooling |

## Before you open a pull request

Run what CI runs. The full Linux quality job is:

```sh
cargo fmt --all --check
./scripts/check-config-schema.sh
python3 scripts/check-docs-links.py
python3 scripts/tests/test_dashboard_asset_provenance.py
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build -p pooler-cli --bin pooler --locked
python3 scripts/check-docs-examples.py --require-binary
cargo test --workspace --all-features --locked
cargo test --workspace --all-features --locked --doc
```

Compatibility fixtures and the deeper hardening suites run in separate jobs:

```sh
./scripts/verify-compatibility-fixtures.py
scripts/deep-test.sh --no-fuzz
```

Clippy runs with `-D warnings`, so a warning fails the build.

## Changing configuration

The source schema is generated, not hand-written. After changing any configuration type, regenerate and verify it:

```sh
./scripts/generate-config-schema.sh
./scripts/check-config-schema.sh
```

Adding a preset parameter means updating the preset source in `presets/`, its expansion and parameter allowlist in `crates/pooler-config/src/loader.rs`, and the table in `docs/adapters-and-presets.md`. Unknown parameters must be rejected; silently ignoring one is a bug.

## Changing protocol behavior

A new adapter or codec path needs a sanitized fixture. Capture one rather than hand-writing it, and never include real credentials or prompts:

```sh
cargo run -p pooler-cli -- fixture capture input.json capture.json
./scripts/verify-compatibility-fixtures.py
```

Bodies are omitted from captures by default. Retaining bounded, recursively redacted JSON bodies requires an explicit `--include-bodies`.

If a request cannot be represented faithfully, honor the route's `loss_policy` rather than degrading quietly. Report the loss through `ConversionReport` so the runtime can reject or degrade deliberately.

## Documentation

Documentation is verified against the binary in CI, so it cannot drift silently.

- `scripts/check-docs-links.py` resolves every relative link and heading anchor.
- `scripts/check-docs-examples.py` compiles every fenced YAML block that declares a top-level `version:` through `pooler check`, and compares every documented "N known providers" claim against `pooler providers --json`.

This means a documentation example must actually work. If you add a complete configuration example, it will be compiled. If you add a partial fragment, omit `version:` so it is treated as a fragment.

Documentation style follows the [Google developer documentation style guide](https://developers.google.com/style): put the key point first, address the reader as *you*, use imperative verbs for instructions, prefer active voice, and use sentence case for headings. Do not describe a task as easy, simple, or obvious.

## Security-sensitive changes

Anything touching authentication, the credential store, the management API, or redaction gets extra scrutiny. Do not send a vulnerability report through a pull request; see [SECURITY.md](SECURITY.md).

When you do change these areas:

- Keep the management listener loopback-only or on an owner-private Unix socket. Remote management is unsupported until management TLS exists.
- Require a configured bearer secret for every mutation, even on loopback.
- Keep management responses metadata-only. Prompts, response bodies, credentials, secret references, and authorization headers must never appear in a response, log, trace, audit event, or export.
- Preserve owner-private file modes: `0700` for directories, `0600` for files holding credential material.
- Keep provider DNS allowlists enforced for built-in OAuth profiles. Endpoint overrides must not be able to redirect OAuth traffic to private, loopback, link-local, or unrelated hosts.

## Dependencies

Dependency and license policy is enforced by `deny.toml` in a dedicated CI job. Add a dependency only when it earns its place, pin it the way neighboring entries in `Cargo.toml` are pinned, and check the policy locally:

```sh
cargo deny check
```

Non-Cargo assets embedded in the dashboard are recorded in `third-party/dashboard-assets/manifest.json` with their version evidence, source, transformation, and license. `scripts/tests/test_dashboard_asset_provenance.py` enforces that. If the generation record does not establish a version or copyright owner, say so in the manifest rather than inferring one.

## Commits and pull requests

Write the commit message for someone debugging this code in a year with no access to the pull request. State what changed and why; describe observable behavior rather than narrating the diff.

Use a short type prefix that matches existing history: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, or `chore:`.

In the pull request, explain the user-visible effect, list the commands you ran to verify it, and call out anything you could not verify. Keep pull requests focused; a mechanical rename and a behavior change belong in separate commits.

## Code style

Rust formatting is `cargo fmt` with the repository defaults, and workspace lints in `Cargo.toml` apply to every crate.

Match the surrounding code. Write a comment only to record a constraint the code cannot express, such as why a bound exists or which provider behavior a branch encodes. Do not narrate what the next line does, and do not leave a comment explaining your change to a reviewer.

Prefer explicit bounds over unbounded input handling. Parsers, bodies, frames, queues, and retained records all carry limits by design; keep it that way.

## Reporting a bug

Include the version (`pooler --version`), the platform, what you expected, and what happened. A redacted diagnostic export is the most useful attachment:

```sh
curl -H "Authorization: Bearer $(cat /path/to/management.token)" \
  http://127.0.0.1:18477/export > pooler-diagnostic-export.json
```

That export contains process status, compiled route metadata, and configuration generations. It contains no secrets, credentials, prompts, or response bodies. Review it before posting anyway.

## License

Pooler is Apache-2.0. By contributing, you agree that your contribution is licensed under those terms.
