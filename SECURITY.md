# Security policy

Pooler sits between developer tools and paid provider accounts, and it stores credentials. We treat vulnerability reports seriously and would rather hear about a suspected problem than miss a real one.

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.**

Use either private channel:

- **GitHub advisory**, preferred: <https://github.com/coder-company/pooler/security/advisories/new>. This keeps the discussion, the fix, and the eventual disclosure in one place, and it lets us credit you.
- **Email**: [c@coder.company](mailto:c@coder.company). Use this if you cannot use GitHub, or if you would rather make first contact by mail.

Either way, tell us the issue, the affected version, the impact, and the smallest reproduction you have.

### What to include

The more of this you can provide, the faster we can act:

- the Pooler version, from `pooler --version`;
- the platform and how Pooler was installed;
- the relevant configuration shape, with every secret reference redacted;
- what an attacker can do, and what access they need to do it;
- a reproduction, ideally a sanitized fixture or a minimal configuration.

**Never include real credentials, tokens, API keys, or prompt content in a report.** If a redacted diagnostic export helps, generate one and review it before attaching:

```sh
curl -H "Authorization: Bearer $(cat /path/to/management.token)" \
  http://127.0.0.1:18477/export > pooler-diagnostic-export.json
```

That export is metadata only by design. It contains no credentials, prompts, or response bodies.

### What to expect

We aim to acknowledge a report within three working days and to give you an initial assessment, including whether we consider it in scope, within seven working days. If a report needs a fix, we will keep you updated as it progresses and coordinate timing with you before disclosing.

Please give us a reasonable opportunity to ship a fix before publishing. We will credit you in the advisory unless you would rather stay anonymous.

## Supported versions

Pooler is pre-1.0. Security fixes land on `main` and in the next release; earlier releases are not patched in place. Track the latest release.

| Version | Supported |
| :--- | :--- |
| Latest release | Yes |
| Earlier releases | No |

## Scope

### In scope

- Credential disclosure of any kind: a token, API key, OAuth client secret, or secret reference value appearing in a log, trace, audit event, management response, dashboard URL, browser storage, or diagnostic export.
- Bypassing management authentication, or performing a mutation without the configured bearer secret.
- Reaching the management API from a non-loopback origin when it is configured for loopback, or defeating its `Origin` checks.
- Redirecting OAuth traffic away from a built-in profile's provider DNS allowlist, including through endpoint overrides.
- Reading or writing outside the intended owner-private paths, or a file being created with modes wider than `0700` for directories or `0600` for credential material.
- Defeating credential-store encryption, or recovering plaintext credentials from the SQLite store without the master key.
- Escaping a documented bound in a way that enables denial of service or memory exhaustion: request bodies, frames, events, queues, retained records, or parser inputs.
- A commit-safety violation where a request already committed to the client is silently replayed against a different account.
- Injection through configuration, presets, or fixtures that leads to code execution or credential access.
- A redaction failure where a prompt, response body, or authorization header is retained or exported.

### Out of scope

- Vulnerabilities in an upstream AI provider's own API or console. Report those to the provider.
- Behavior that requires an attacker to already have the ability to read your owner-private files or your environment variables. Pooler's threat model assumes those are protected by the operating system.
- Binding the management listener to a public interface yourself. Remote management is explicitly unsupported until management TLS exists, and Pooler refuses to launch a browser dashboard for a non-loopback bind.
- Configuring a custom OAuth endpoint override behind the deliberately conspicuous `--dangerously-allow-custom-oauth-endpoints` boundary.
- Provider quota exhaustion or cost incurred by your own configured accounts.
- Missing hardening that has no demonstrated impact, or automated scanner output with no working reproduction.
- Reports about dependency advisories with no exploitable path in Pooler. Dependency policy is enforced by `deny.toml` in CI; open a normal issue for those.

If you are unsure whether something is in scope, report it privately and let us decide.

## Design commitments

These are properties Pooler intends to hold. A demonstrated violation of any of them is a vulnerability, not a feature request.

**Secrets are referenced, never inlined.** Configuration accepts only `env:`, `file:`, or `keyring:` references. A literal secret is rejected by the compiler, and an API key is never accepted as a command-line argument.

**Management is loopback-only and authenticated.** The listener stays on loopback or an owner-private Unix socket. Every mutation requires a configured bearer secret, even on loopback. Tokens travel in an `Authorization` header, never in a URL.

**Management data is metadata.** Accounts, request history, usage, traces, audit events, and exports carry identifiers, timings, and outcomes. Credential payloads, secret reference values, raw prompts and responses, request bodies, and authorization headers are never stored or exported.

**Credentials are encrypted at rest.** The SQLite store holds authenticated encrypted envelopes bound to their row identity, keyed from a master secret you supply by reference. An unencrypted store refuses to persist request history or usage rather than writing metadata in plaintext.

**OAuth cannot be redirected.** Built-in provider profiles enforce provider DNS allowlists that endpoint overrides cannot bypass. Browser flows use a loopback callback with state validation and S256 PKCE. Device flows keep device codes and token responses server-side.

**Everything is bounded.** Parsers, request bodies, frames, events, queues, retained records, and exports all carry explicit limits, and exceeding one is an error rather than unbounded growth.

**Unsupported behavior is rejected.** Pooler does not silently advertise or discard protocol behavior it cannot represent. A route that cannot faithfully convert a request fails according to its `loss_policy`.

## Verifying your own deployment

Two commands check a local installation, and neither sends a billable request:

```sh
pooler doctor      # configuration, ports, file permissions, store integrity
pooler preflight   # DNS, TLS, endpoint reachability; reports inference_requests_sent: 0
```

Release artifacts are reproducible and signed. Each release publishes per-target archives, a `SHA256SUMS` manifest, a Sigstore bundle for that manifest, and CycloneDX and SPDX bills of material. Verify the checksum manifest before trusting a downloaded archive; the installer does this automatically. See [release](docs/release.md).
