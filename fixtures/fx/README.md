# Vercel Labs fx fixtures

`fx-0.0.3-cliproxy-tool-loop.json` is a sanitized, deterministic behavior
fixture for the installed Vercel Labs `fx` 0.0.3 client wire. Its event shape
is anchored to the working local bridge at
`/home/chaitanya/fx-cliproxy-bridge/server.mjs`; no credential, provider URL,
workspace prompt, or live response is included.

The fixture exercises both halves of a tool loop. The first streamed response
contains the OpenAI-compatible `reasoning` delta alias and fragmented tool
arguments. They must become the fx reasoning lifecycle and one completed
`tool-call` event before the `finish` event. The follow-up request contains the
nested fx `tool-result` part and must become an OpenAI `role: tool` message with
the exact invocation ID and result text. This deliberately improves on the
temporary Node bridge, which stringifies the whole tool content array and can
lose the nested invocation ID.

The model-catalog case verifies that Pooler preserves provider-declared tags,
reasoning options, and metadata but never invents those capabilities for
models whose upstream entries omit them.

Replay the fixture at the native adapter boundary with:

```sh
cargo test -p adapter-fx --test fx_tool_loop --locked
```

This is deterministic protocol evidence. Live installed-client evidence is
recorded separately and must not be inferred from this fixture.
