# adapter-xai

Provider-isolated xAI compatibility code. The crate owns JSON conversion and
state only; it does not open sockets, read credentials, or register routes.

Server hook surface:

- Before an xAI HTTP attempt, call `XaiRestAdapter::prepare_request` with the
  selected endpoint, `XaiRestTransport::Http`, the bounded request body, and
  the route loss policy. Forward `PreparedXaiRestRequest::body` only after the
  returned conversion report is accepted.
- For a semantic Chat route, use `XaiRestAdapter::decode_chat_request` on
  ingress and `XaiRestAdapter::encode_chat_request` on egress to xAI.
- After a successful WebSocket upgrade to `wss://api.x.ai/v1/responses`, call
  `XaiRealtimeRequestCodec::encode_response_create` for each turn and send its
  body as one text message.
- Feed each upstream text-message payload into one connection-owned
  `XaiRealtimeEventDecoder`. Route `semantic_events` through the ordinary
  semantic response pipeline, or forward `raw` for a native xAI route. Call
  `finish` when the socket closes.

The WebSocket codec intentionally has no `tokio-tungstenite` dependency. Frame
I/O, masking, ping/pong, close handling, TLS, authentication, cancellation, and
the 25-minute reconnect policy remain transport/runtime responsibilities.
