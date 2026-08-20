# xAI compatibility fixtures

These are synthetic, secret-free conformance fixtures derived from xAI's
public API documentation on 2026-08-20. They are not captured production
traffic and do not establish live-provider authorization.

Sources:

- <https://docs.x.ai/developers/rest-api-reference/inference/chat>
- <https://docs.x.ai/developers/advanced-api-usage/websocket-mode>

`chat-completions-request.json` covers OpenAI-compatible Chat plus xAI search,
priority, cache-key, and reasoning fields. `responses-websocket-request.json`
covers a stateful `response.create` continuation. The JSONL files exercise
text, function-call, completion, usage, and xAI-specific error events. Each
JSONL line is one WebSocket text-message payload.

Replay with:

```console
cargo test -p adapter-xai --test xai_fixtures --locked
```
