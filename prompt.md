# Finish Pooler

You are the primary implementation agent for Pooler.

Repository: `/home/chaitanya/codevault/pooler`

## Objective

Finish every remaining product gap so Pooler genuinely exceeds CLIProxyAPI Plus in turnkey endpoint breadth, native provider integration, safe management, request investigation, usage accounting, onboarding, and release quality.

Do not stop at scaffolding, types, endpoint constants, permissive mocks, opaque placeholders, or documentation. A capability is complete only when it has a production consumer, correct authentication and endpoint behavior, bounded runtime integration, boundary tests, honest compatibility evidence, and matching documentation.

## Required reading

Read completely before editing:

- `/home/staticpayload/AGENTS.md`
- `GOAL.md`
- `pooler-readgold.md`
- `ARCHITECTURE_PLAN.md`
- `docs/cliproxyapi-feature-gap.md`
- `docs/gateway.md`
- `docs/management.md`
- `docs/provider-catalog.md`
- `docs/provider-login.md`
- `docs/release-acceptance.md`

Apply the `keep-code-boring` skill to every line and decision:

`https://github.com/coder-company/skills/blob/main/skills/engineering/keep-code-boring/SKILL.md`

Optimize in this order:

1. Correctness
2. Security and privacy
3. Clarity
4. Simplicity
5. Maintainability
6. Performance
7. Concision

Reuse existing abstractions. Fix behavior at the narrowest owning boundary. Do not build speculative frameworks or duplicate business logic.

## Operating rules

- Work directly on `main` only.
- Do not create, switch to, or use another branch.
- Fetch before integrating and detect unexpected concurrent changes.
- Preserve all valid existing work.
- Make focused commits for complete workstreams.
- Push `main` after verified commits.
- Never force-push or rewrite published history.
- Never count a merge as verification.
- Use at most two concurrent sub-agents.
- Give sub-agents concrete, non-overlapping responsibilities.
- Avoid concurrent Cargo commands sharing one target directory.
- Tell every implementation agent to apply `keep-code-boring`.
- Do not expose credentials, OAuth tokens, secret references, prompts, responses, or authorization headers through management APIs, logs, exports, or browser storage.
- Do not invent undocumented OAuth clients, endpoints, proprietary secrets, or compatibility.
- Do not claim queued, skipped, cancelled, or unavailable CI as passing.

## Current baseline

The previously separate product-gap branch has been fast-forwarded into `main`.

Preserve the good work:

- The catalog test upstream now owns its listener for the complete proxy lifetime. Do not restore wall-clock listener shutdowns or hide races with arbitrary sleeps.
- The gateway preset mounts common endpoint paths with explicit bounds.
- Existing setup wizard, management security, catalog, account pooling, adapters, and compatibility work must remain intact.

Known release failure:

- The exact-SHA Hardening AddressSanitizer job reported 105 leaked bytes in seven allocations in the `pooler-extension` sanitizer workload.
- Reproduce and fix the ownership leak. Do not suppress LeakSanitizer or disable the test.

## Workstream 1: repair the gateway correctly

The current gateway proves reachability through a permissive loopback upstream. It is not yet universal provider compatibility.

### Preserve provider-specific authentication

The preset currently supplies complete bearer authentication, overriding `known_provider` authentication placement.

Fix the configuration model so a preset can override only the protected credential reference while retaining the provider's:

- authentication kind;
- header name;
- value prefix;
- required query placement; and
- client-header sanitization rules.

Required tests:

- bearer provider receives only the configured bearer credential;
- Anthropic receives only `x-api-key` and required version headers;
- Gemini receives only its documented Google key placement;
- arbitrary-header providers receive the exact configured header and prefix;
- client-supplied credential header sentinels are stripped;
- no credential is rendered, logged, exported, or embedded.

### Mount only compatible endpoint families

Do not send OpenAI, Anthropic, and Gemini paths to an arbitrary single provider without translation.

Use provider integration facts to include only supported same-wire routes. Cross-protocol routes require real semantic decoder/encoder pairs. Reject unsupported provider/endpoint combinations during compilation.

Replace permissive upstream tests with strict OpenAI, Anthropic, and Gemini provider fakes that reject wrong paths, headers, queries, content types, and body shapes.

### Implement a real `/v1/models`

Serve Pooler's active model view rather than blindly forwarding the upstream model list.

The response must account for:

- public aliases and exclusions;
- runtime model enablement;
- account eligibility;
- provider health and quota availability;
- gateway compatibility and model capabilities;
- configuration/catalog generation.

Return a stable OpenAI-compatible shape without leaking internal account IDs, secret references, or upstream endpoints.

### Route Gemini path models

Implement strict Gemini model/action path parsing, public alias resolution, upstream model rewriting, account selection, capability filtering, and query preservation for:

- model list and model GET;
- `generateContent`;
- `streamGenerateContent`;
- `countTokens`;
- Gemini Interactions.

### Mount semantic Responses WebSocket

For OpenAI/Codex, use Pooler's semantic Responses WebSocket implementation rather than only an opaque tunnel.

Preserve tools, reasoning, usage, errors, terminal state, continuation, cancellation, and commitment. Isolate reuse by session, account, profile, endpoint, and credential generation. Enforce idle/absolute age and all frame/queue bounds. Reject unsupported provider combinations before upstream execution.

## Workstream 2: fix sanitizer and restore green gates

Reproduce the failed workflow command exactly:

```sh
POOLER_REQUIRE_SANITIZER=1 \
POOLER_SANITIZER=address \
scripts/deep-test.sh --sanitize --no-fuzz
```

Trace and fix the leaked ownership in `pooler-extension`. Prove child processes, pipes, tasks, handles, buffers, and temporary resources return to zero. Add a regression that fails under the old lifecycle.

Then rerun CI, Hardening, and Secret Scan against the new exact SHA.

## Workstream 3: OpenAI and Codex endpoints

Implement and mount:

- Responses Compact;
- semantic Responses WebSocket;
- Alpha Search when supported by authoritative evidence;
- OpenAI Realtime WebSocket;
- Realtime client secrets and sessions;
- transcription and translation sessions;
- sideband connections;
- SIP accept, reject, refer, and hangup only when the selected provider supports them.

Use authoritative OpenAI documentation and the installed Pi implementation as protocol evidence. Model audio, interruption, tools, reasoning, terminal state, reconnection, cancellation, and commitment explicitly. Never replay after downstream commitment.

## Workstream 4: native media lifecycles

Implement provider-native runtime behavior for:

- image generation and editing;
- image result retrieval;
- audio transcription where supported;
- video creation, editing, extension, polling, retrieval, and download;
- media-related Responses events.

Reuse the existing bounded media/multipart codecs. Stream large bodies. Bound polling and retained state. Preserve same-wire fields and account explicitly for cross-provider loss. Add strict provider fixtures and mounted server E2Es.

## Workstream 5: mounted native providers

Turn the existing contracts for these providers into real runtime integrations:

- Kimi;
- Vertex;
- AI Studio;
- Antigravity;
- special OpenAI-compatible providers requiring nonstandard behavior.

For each provider implement:

- production runtime registration;
- endpoint construction;
- auth placement and sanitization;
- model discovery;
- documented account identity;
- request/token/project/credit quota classification;
- error mapping;
- model dialect and capabilities;
- retry/cooldown causation;
- mounted `HttpProxyServer` E2Es;
- sanitized fixtures.

Use documented OAuth, device, or service-account flows only. For undocumented flows, support owner-private imported profiles instead of guessing. Keep API-key and subscription identities separate and test mixed-account failover.

## Workstream 6: typed durable configuration

Do not copy CLIProxyAPI's raw unrestricted YAML or secret-bearing browser model.

Implement:

```text
active generation
  -> create draft
  -> apply typed patches
  -> compile and validate
  -> semantic diff
  -> explicit confirmation
  -> atomic persistence with backup
  -> publish/reload
  -> audited result
  -> rollback
```

Support providers, upstreams, accounts, pools, routes, policies, catalog sources, aliases, exclusions, model overrides, retry settings, listeners, and extension declarations.

Require base-generation/ETag protection, secret references only, owner-private files, symlink/path rejection, atomic replace, fsync, backup, rollback, and accessible browser tests. If arbitrary user YAML cannot be preserved, write an explicitly managed generated file rather than rewriting it destructively.

## Workstream 7: redacted request explorer

Use one logical request ID across admission, selection, attempts, retry/failover, commitment, and completion.

Add:

```text
GET /requests
GET /requests/{id}
GET /requests/{id}/timeline
```

Record bounded metadata only: route, listener, public/upstream model, provider, account pseudonym, attempts, eligibility, retry reason, commitment, TTFT, latency, status/error class, quota/cooldown effects, semantic-loss decisions, generations, and optional body hashes.

Never retain raw prompts, responses, credentials, authorization headers, or secret references by default. Add pagination, filters, retention, encrypted persistence when enabled, exports, and a dashboard timeline.

## Workstream 8: historical usage ledger

Implement encrypted bounded storage for:

- input, output, reasoning, and cache tokens;
- explicitly reported image/audio/video units;
- provider/model/account/route dimensions;
- latency and TTFT;
- service tier and result class;
- cost and provenance: `provider_reported`, `operator_estimated`, or `unknown`;
- configuration/catalog generation.

Never invent prices. Operator price books must be explicit and versioned. Add retention, aggregation, bounded cardinality, Prometheus/OTel/JSON export, and dashboard time-range views.

## Workstream 9: onboarding and operations

Implement:

- `pooler init` or a secure supervised bootstrap;
- owner-private starter configuration;
- generated management token and credential-store guidance;
- dashboard launch;
- DNS/TLS/auth/discovery/endpoint/quota preflight;
- brokered dashboard OAuth for documented flows, with tokens remaining server-side;
- typed account creation;
- env/file/keyring reference selection;
- client-specific setup instructions;
- `pooler migrate cliproxy --dry-run`;
- a thin TUI backed entirely by the management API;
- a bounded provider test console.

Do not duplicate runtime logic in the TUI or browser.

## Workstream 10: evidence and release

Required local gates:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --workspace --all-features --doc
cargo audit --deny warnings
cargo deny check
./scripts/check-config-schema.sh
./scripts/check-compatibility-report.sh
./scripts/verify-compatibility-fixtures.py
python3 scripts/test-management-ui-browser.py --require-playwright
python3 scripts/tests/test_dashboard_asset_provenance.py
git diff --check
```

Required final evidence:

- exact-SHA CI, Hardening, and Secret Scan;
- three-run release benchmark;
- 15-minute mixed-protocol stress test;
- comparison against current CLIProxyAPI Plus;
- live-provider conformance for every advertised native provider;
- Linux x86_64/ARM64 and macOS x86_64/ARM64 artifacts;
- checksums, signatures, SBOM, and provenance.

If external macOS capacity or signing credentials are unavailable, report them as external blockers. Do not claim completion.

Update all status, gateway, compatibility, comparison, and release documentation. For every capability distinguish declared, mounted, runtime-consumed, fixture-verified, current-client verified, live-provider verified, and released.

## Execution order

1. Repair provider-aware gateway behavior.
2. Fix the sanitizer leak.
3. Restore exact-SHA green CI/Hardening/Secret Scan.
4. Implement OpenAI/Codex endpoints.
5. Implement native media.
6. Mount native providers.
7. Implement typed durable configuration.
8. Implement request explorer.
9. Implement usage ledger.
10. Finish bootstrap, OAuth, migration, and TUI.
11. Run live conformance, benchmark, stress, and release gates.

After each workstream, run focused tests, obtain an independent review, fix all correctness/security findings, commit, and push `main`.

## Completion definition

The work is complete only when every advertised endpoint and provider has a real runtime consumer; authentication and routing are provider-correct; durable mutations are validated and rollback-safe; request and usage history are redacted and bounded; full workspace and sanitizer gates pass; exact-SHA CI is green; compatibility claims match executable evidence; all authorized work is committed and pushed to `main`; and remaining external blockers are reported without overstating completion.
