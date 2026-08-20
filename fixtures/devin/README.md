# Devin reference fixtures

These sanitized wire fixtures are grounded in the `widevin` reference source
at commit `6c48392052caaecca820ec41df9d87ed818dfc21`:

`/home/chaitanya/devin-local-bridge-upstream/rust/fixtures`

The two model-discovery fixtures are copied byte-for-byte from that snapshot.
The Connect fixture uses the same minimal Prost schema and sanitized values as
the snapshot's `rust/tests/chat.rs` and `rust/tests/connect.rs` tests. It keeps
the complete encoded request and response envelopes so tests can verify wire
bytes, protobuf fields, gzip decompression, arbitrary transport fragmentation,
tool-call accumulation, identifiers, and usage accounting.

No credentials, customer content, or live service responses are included.
The fixture source project is [widevin](https://github.com/dante-teo/widevin)
and is MIT-licensed; its schema source is documented in the upstream notice as
the Devin/Cascade definitions from
[`can1357/oh-my-pi`](https://github.com/can1357/oh-my-pi). The applicable notice
is preserved in [`LICENSE.widevin`](LICENSE.widevin).

`current-client-tool-follow-up.json` is separate current-client evidence. It
retains the sanitized second-turn request shape observed from Devin CLI
`3000.4.16`: assistant tool-call context followed by a `source=Tool` result.
Its runtime replay verifies Connect/protobuf decoding, assistant/tool OpenAI
roles, model forwarding, and a deterministic final text/usage/completion
response through `HttpProxyServer`:

```sh
cargo test -p pooler-server --test current_client_compatibility \
  devin_current_tool_follow_up_replays_through_http_proxy_server --locked
```

The committed fixture does not retain or replay the initial tool-call response,
OS command execution, client orchestration, or a live-provider response.
