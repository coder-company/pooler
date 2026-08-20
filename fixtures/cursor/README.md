# Cursor current-client evidence

`cursor-agent-local-2026.08.04.json` records a sanitized run of the installed
Cursor Agent CLI version `2026.08.04-aaa8809` through Pooler on 2026-08-20.
The agent ran in authless mode with an isolated temporary workspace. Pooler
used the Cursor preset on a loopback listener and forwarded to a deterministic
loopback Chat Completions server.

The live client returned `POOLER_CURSOR_LIVE_OK` with exit status zero. The
loopback server observed a streaming request for model `gpt-5.6-sol`, and the
forwarded request contained Pooler's configured `reasoning_effort: high`
transform.

The fixture intentionally replaces system and user prompt text with redaction
markers and omits authorization, client identity, and transport headers. It
proves the exercised client/request path only; it does not authorize a live
provider or establish tool, media, or broader Cursor compatibility.

Replay a captured sanitized actual fixture with:

```sh
cargo run -p pooler-cli -- fixture replay \
  fixtures/cursor/cursor-agent-local-2026.08.04.json \
  --actual <sanitized-actual-fixture>
```
