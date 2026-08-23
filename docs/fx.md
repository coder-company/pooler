# Vercel Labs fx

Pooler's `fx` preset provides a native, bounded Rust adapter for the Vercel
Labs `fx` terminal agent. It is not the Factory Droid client or the legacy
`factory` preset.

The preset exposes:

- `POST /v3/ai/language-model` and `/v4/ai/language-model`;
- `GET /coding-agent/v1/models` and `/v1/models`;
- OpenAI Chat Completions upstream translation;
- fx text and reasoning SSE lifecycles;
- one completed fx `tool-call` event assembled from fragmented OpenAI deltas;
- nested fx tool-result follow-up translation with the exact tool-call ID;
- upstream model metadata without invented per-model capabilities; and
- a `type: language` discovery default only when the upstream omits `type`.

Start Pooler against a CLIProxyAPI-compatible upstream without placing a key
in a configuration file:

```sh
export CLIPROXY_API_KEY='...'
cargo run -p pooler-cli -- check --config config/fx.example.yaml
cargo run -p pooler-cli -- serve --config config/fx.example.yaml
```

Point the installed client at Pooler. `AI_GATEWAY_API_KEY` only unlocks the fx
client; Pooler removes that downstream authorization value and supplies the
separate `CLIPROXY_API_KEY` secret configured on its upstream.

```sh
AI_GATEWAY_API_KEY=pooler-local \
FX_GATEWAY_BASE_URL=http://127.0.0.1:18475 \
FX_GATEWAY_CHAT_URL=http://127.0.0.1:18475/v3/ai/language-model \
fx ask 'Explain this repository'
```

The `fx` preset uses `loss_policy: degrade` for chat because the fx wire cannot
represent optional OpenAI response IDs and detailed usage fields. Required
tool-call and tool-result semantics are preserved. The model catalog routes
use `loss_policy: reject`.

The deterministic tool-loop fixture and replay instructions are in
[`fixtures/fx/README.md`](../fixtures/fx/README.md).
