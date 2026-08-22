# Typed durable configuration

Pooler's authenticated management listener can edit the serving configuration without exposing raw YAML, credential values, or secret references to a browser. The dashboard's **Configuration** view and the JSON API use the same bounded draft lifecycle:

1. create a draft from the active rendered source;
2. apply section-scoped typed operations;
3. compile and validate the complete candidate;
4. review a value-free semantic diff;
5. submit the one-time confirmation token;
6. persist an owner-private generated sidecar atomically;
7. reload and publish it through the normal generation gate; and
8. retain a bounded audited outcome and rollback target.

This feature is enabled automatically by `pooler serve --config PATH` when the configuration enables an authenticated management listener. Pooler never rewrites `PATH`. It writes `NAME.managed.yaml` beside the original file with a generated-file banner. On a later start with the same `PATH`, Pooler selects that sidecar only when it is a safe owner-private regular file carrying Pooler's exact generated marker; otherwise startup fails closed or, when no sidecar exists, uses `PATH`. To abandon managed state, stop Pooler and move both the managed sidecar and its sibling `NAME.managed.backup.yaml` aside; the next start uses the operator source.

## Safety model

- Management bearer authentication, loopback `Host` validation, and same-origin mutation checks still apply before any typed mutation body is read. Typed JSON bodies are limited to 256 KiB and a five-second read deadline.
- Drafts are process-local, expire after 30 minutes, and are bounded to 8 drafts, 128 patches per draft, and a 4 MiB rendered document.
- Every patch needs the current draft `If-Match` value. Commit additionally checks the active base generation and a one-time token returned by validation.
- Rollback needs `If-Match: generation-N` for the active generation and `{"confirm":"rollback"}`.
- Only section operations are accepted. JSON Pointer, arbitrary YAML replacement, and unknown fields are rejected.
- The ordinary configuration compiler is the final authority. Account, management, TLS, and extension secrets must remain `env:`, `file:`, `command:`, or supported credential-store references; literal secret values fail validation.
- API views and semantic diffs contain IDs and change kinds, not configuration values, OAuth material, credentials, or secret references.
- The original configuration, destination, backup, and temporary files are checked for symlinks and unsafe file types. Existing generated files must be regular, singly linked, owned by the serving user, and inaccessible to group/other users.
- Persistence uses a new owner-only temporary file, file `fsync`, atomic rename, permission enforcement, and directory `fsync`. A pre-existing generated file is backed up with the same rules; failed commits and rollbacks restore both the managed revision and the previous rollback target.
- The generated sidecar is sent to the normal compile/reload/publication path. A failed publication restores the prior filesystem state; the active runtime generation does not change.
- Only one managed commit or rollback may be in flight. This avoids reordering backups or generation preconditions.

## API

All paths below are relative to `/management`.

| Method and path | Purpose |
| --- | --- |
| `GET /config` | Active generation, generation ETag, and whether typed drafts are enabled. |
| `POST /config/drafts` | Create a draft. Body must be empty. |
| `GET /config/drafts/{id}` | Return bounded draft metadata, never the document. |
| `PATCH /config/drafts/{id}` | Apply one typed operation; requires `If-Match`. |
| `POST /config/drafts/{id}/validate` | Compile and return a value-free semantic diff and confirmation token; body empty, `If-Match` required. |
| `GET /config/drafts/{id}/diff` | Return the current value-free structural diff. |
| `POST /config/drafts/{id}/commit` | Persist and queue reload using `{"confirmation_token":"..."}` and `If-Match`. |
| `POST /config/rollback` | Restore the previous generated revision using generation `If-Match` and explicit confirmation. |

A patch is one of:

```json
{"op":"upsert","section":"models","id":"public-model","value":{"id":"public-model","targets":[{"provider":"openai","upstream_model":"gpt-5"}]}}
```

```json
{"op":"remove","section":"routes","id":"legacy-route"}
```

```json
{"op":"replace","section":"catalog","value":{"sources":[],"refresh":{},"overrides":[]}}
```

`upsert` and `remove` support `listeners`, `upstreams` (provider declarations), `accounts`, `credentials`, `account_pools`, `policies` (including retry policy), `extensions`, `models`, and `routes`. Typed `replace` supports `catalog` (sources, aliases, inclusion/exclusion rules, refresh settings, and model overrides), `management`, and the complete explicit `usage_price_book`. Compilation rejects any malformed or incomplete typed value.

A successful commit or rollback returns `202 Accepted` with a reload request ID. Follow `/management/reloads` for the final audited result; acceptance is not publication.

## Browser accessibility and verification

The embedded dashboard uses labelled controls, keyboard-operable buttons, visible status banners, value-free diff text, responsive layouts, and the existing strict CSP. The bearer token and draft state remain in memory only—never local storage, session storage, cookies, URLs, or downloads.

Run deterministic browser coverage with:

```bash
python3 scripts/test-management-ui-browser.py --require-playwright
```

The test exercises keyboard/navigation state, labelled controls, responsive overflow, typed JSON patch shape, bearer and ETag headers, validation, semantic diff, explicit commit and destructive rollback confirmation, and browser-storage absence.
