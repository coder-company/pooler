//! Mounted behaviour of the gateway preset that provider conformance does not
//! already cover.
//!
//! Per-provider wire conformance lives in `gateway_provider_auth.rs`, which
//! judges every request with a strict provider fake. This file covers what is
//! specific to the preset itself: an unknown caller field surviving a patch
//! route, the semantic Responses WebSocket transport, and the bounded native
//! WebSocket tunnel.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use http::{header, HeaderValue};
use pooler_auth::MemoryOAuthTokenStore;
use pooler_http::NativeRuntime;
use pooler_server::HttpProxyServer;
use pooler_testkit::{ProviderContract, StrictProvider};
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_tungstenite::{
    accept_async, accept_hdr_async,
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{Request, Response},
        Message,
    },
};

const SECRET: &str = "gateway-test-key";

/// A fake WebSocket upstream that echoes text messages.
async fn spawn_websocket_upstream() -> (SocketAddr, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("websocket upstream bind");
    let address = listener.local_addr().expect("websocket upstream address");
    let task = tokio::spawn(async move {
        let mut observed = Vec::new();
        let (stream, _) = listener.accept().await.expect("websocket upstream accepts");
        let mut socket = accept_async(stream).await.expect("websocket handshake");
        while let Some(message) = socket.next().await {
            match message.expect("websocket message") {
                Message::Text(text) => {
                    observed.push(text.to_string());
                    socket.send(Message::Text(text)).await.expect("echo");
                }
                Message::Close(frame) => {
                    let _ = socket.send(Message::Close(frame)).await;
                    break;
                }
                _ => {}
            }
        }
        observed
    });
    (address, task)
}

/// A strict OpenAI Responses WebSocket that serves two fixture turns on one connection.
async fn spawn_semantic_responses_upstream(
    provider_turns: Vec<Vec<Value>>,
) -> (SocketAddr, JoinHandle<(bool, Value, Value)>) {
    let mut provider_turns = provider_turns.into_iter();
    let first_events = provider_turns.next().expect("first provider turn");
    let second_events = provider_turns.next().expect("second provider turn");
    assert!(
        provider_turns.next().is_none(),
        "exactly two provider turns"
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("semantic websocket upstream bind");
    let address = listener.local_addr().expect("semantic upstream address");
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("semantic upstream accepts");
        let mut authorized = false;
        let mut socket = accept_hdr_async(stream, |request: &Request, response| {
            authorized = request.headers().get(header::AUTHORIZATION)
                == Some(&HeaderValue::from_static("Bearer gateway-test-key"))
                && request.headers().get("openai-beta")
                    == Some(&HeaderValue::from_static("responses_websockets=2026-02-06"));
            Ok(response)
        })
        .await
        .expect("semantic websocket handshake");

        let first = socket
            .next()
            .await
            .expect("first response.create")
            .expect("first websocket message")
            .into_text()
            .expect("first request text");
        let first: Value = serde_json::from_str(&first).expect("first request JSON");
        for event in first_events {
            socket
                .send(Message::Text(event.to_string().into()))
                .await
                .expect("first-turn provider event");
        }

        let second = socket
            .next()
            .await
            .expect("second response.create")
            .expect("second websocket message")
            .into_text()
            .expect("second request text");
        let second: Value = serde_json::from_str(&second).expect("second request JSON");
        for event in second_events {
            socket
                .send(Message::Text(event.to_string().into()))
                .await
                .expect("second-turn provider event");
        }
        let _ = socket.close(None).await;
        (authorized, first, second)
    });
    (address, task)
}

async fn spawn_openai_realtime_upstream() -> (
    SocketAddr,
    JoinHandle<(String, bool, Vec<String>, Vec<Value>)>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Realtime upstream bind");
    let address = listener.local_addr().expect("Realtime upstream address");
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("Realtime upstream accepts");
        let mut path = String::new();
        let mut authorized = false;
        let mut protocols = Vec::new();
        let mut socket = accept_hdr_async(stream, |request: &Request, mut response: Response| {
            path = request.uri().to_string();
            authorized = request.headers().get(header::AUTHORIZATION)
                == Some(&HeaderValue::from_static("Bearer gateway-test-key"));
            protocols = request
                .headers()
                .get_all("sec-websocket-protocol")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .map(str::to_owned)
                .collect();
            response.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static("realtime"),
            );
            Ok(response)
        })
        .await
        .expect("Realtime upstream handshake");

        socket
            .send(Message::Text(
                r#"{"type":"session.created","event_id":"evt_session","session":{"id":"sess_1","type":"realtime"}}"#
                    .into(),
            ))
            .await
            .expect("session.created");

        let mut client_events = Vec::new();
        for _ in 0..4 {
            let message = socket
                .next()
                .await
                .expect("Realtime client event")
                .expect("Realtime client message")
                .into_text()
                .expect("Realtime client text");
            client_events.push(serde_json::from_str(&message).expect("Realtime client JSON"));
        }

        for event in [
            r#"{"type":"response.created","event_id":"evt_created","response":{"id":"resp_1","status":"in_progress"}}"#,
            r#"{"type":"response.output_audio.delta","event_id":"evt_audio","response_id":"resp_1","item_id":"item_1","output_index":0,"content_index":0,"delta":"AQI="}"#,
            r#"{"type":"response.function_call_arguments.delta","event_id":"evt_tool","response_id":"resp_1","item_id":"call_1","output_index":1,"call_id":"call_1","delta":"{\"city\":\"Paris\"}"}"#,
        ] {
            socket
                .send(Message::Text(event.into()))
                .await
                .expect("Realtime provider event");
        }

        for _ in 0..2 {
            let message = socket
                .next()
                .await
                .expect("Realtime interruption event")
                .expect("Realtime interruption message")
                .into_text()
                .expect("Realtime interruption text");
            client_events.push(serde_json::from_str(&message).expect("interruption JSON"));
        }
        socket
            .send(Message::Text(
                r#"{"type":"response.done","event_id":"evt_done","response":{"id":"resp_1","status":"cancelled"}}"#
                    .into(),
            ))
            .await
            .expect("response.done");
        let _ = socket.close(None).await;
        (path, authorized, protocols, client_events)
    });
    (address, task)
}

async fn spawn_openai_sideband_upstream() -> (SocketAddr, JoinHandle<(String, bool, Vec<String>)>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("sideband upstream bind");
    let address = listener.local_addr().expect("sideband upstream address");
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("sideband upstream accepts");
        let mut path = String::new();
        let mut authorized = false;
        let mut protocols = Vec::new();
        let mut socket = accept_hdr_async(stream, |request: &Request, mut response: Response| {
            path = request.uri().to_string();
            authorized = request.headers().get(header::AUTHORIZATION)
                == Some(&HeaderValue::from_static("Bearer gateway-test-key"));
            protocols = request
                .headers()
                .get_all("sec-websocket-protocol")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .map(str::to_owned)
                .collect();
            response.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static("realtime"),
            );
            Ok(response)
        })
        .await
        .expect("sideband upstream handshake");
        socket
            .send(Message::Text(
                r#"{"type":"session.created","event_id":"evt_sideband","session":{"id":"sess_sideband","type":"realtime"}}"#
                    .into(),
            ))
            .await
            .expect("sideband session.created");
        while let Some(message) = socket.next().await {
            if matches!(message.expect("sideband message"), Message::Close(_)) {
                break;
            }
        }
        (path, authorized, protocols)
    });
    (address, task)
}

async fn send_json_request(proxy: &str, path: &str, headers: &str, body: &[u8]) -> String {
    let mut downstream = TcpStream::connect(proxy).await.expect("proxy connection");
    downstream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("JSON request headers");
    if let Err(error) = downstream.write_all(body).await {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ),
            "JSON request body: {error}"
        );
    }
    let mut response = Vec::new();
    downstream
        .read_to_end(&mut response)
        .await
        .expect("JSON response");
    String::from_utf8(response).expect("JSON response UTF-8")
}

async fn send_responses_request(proxy: &str, body: &[u8]) -> String {
    send_json_request(
        proxy,
        "/v1/responses",
        "session-id: mounted-session\r\n",
        body,
    )
    .await
}

/// Compile the shipped preset the way an operator imports it, with the sample
/// endpoints replaced by loopback addresses.
fn gateway_config(
    directory: &TempDir,
    upstream: SocketAddr,
    websocket: SocketAddr,
) -> pooler_config::CompiledConfig {
    let mut secret_file = tempfile::NamedTempFile::new_in(directory.path()).expect("secret file");
    secret_file
        .write_all(SECRET.as_bytes())
        .expect("secret contents");
    let (_, secret) = secret_file.keep().expect("secret persists");
    let secret = secret.display();
    let path = directory.path().join("gateway.yaml");
    std::fs::write(
        &path,
        format!(
            "imports:\n  - preset: gateway\n    as: gateway\n    with:\n      bind: 127.0.0.1:0\n      upstream_url: http://{upstream}\n      websocket_url: ws://{websocket}\n      secret: 'file:{secret}'\n\nversion: 1\n"
        ),
    )
    .expect("gateway config");
    pooler_config::Config::from_path(&path)
        .expect("gateway preset loads")
        .compile()
        .expect("gateway preset compiles")
}

/// Bind the gateway the way `pooler serve` does. A `known_provider` upstream
/// carries a native kind, so the server needs a real native runtime.
async fn bind_gateway(config: pooler_config::CompiledConfig) -> HttpProxyServer {
    let native = Arc::new(
        NativeRuntime::new(&config, Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime"),
    );
    HttpProxyServer::bind_with_native_runtime(config, native)
        .await
        .expect("gateway binds")
}

#[tokio::test]
async fn the_gateway_preset_preserves_the_caller_body_and_rewrites_only_the_model() {
    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let (websocket_address, websocket_task) = spawn_websocket_upstream().await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"vendor_extension":{"keep":"me"}}"#;
    let mut downstream = TcpStream::connect(&proxy).await.expect("proxy connection");
    downstream
        .write_all(
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("downstream headers");
    downstream.write_all(body).await.expect("downstream body");
    let mut response = Vec::new();
    downstream
        .read_to_end(&mut response)
        .await
        .expect("downstream response");
    let response = String::from_utf8_lossy(&response).to_string();

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let log = upstream.finish().await;
    websocket_task.abort();

    log.assert_accepted_everything();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let request = log
        .accepted_for("/v1/chat/completions")
        .expect("the chat request reached the upstream");
    assert!(
        request.body.contains("\"vendor_extension\""),
        "an unknown caller field must survive a patch route: {}",
        request.body
    );
    assert!(
        request.body.contains("\"messages\""),
        "the caller's payload must survive: {}",
        request.body
    );
    assert!(
        request.body.contains("\"model\":\"gpt-4o\""),
        "the model must resolve to the requested target: {}",
        request.body
    );
}

#[tokio::test]
async fn responses_compact_replays_the_documented_same_wire_shape() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/openai/responses-compact-2026-08-21.json");
    let fixture: Value = serde_json::from_str(MANIFEST_FIXTURE).expect("Responses Compact fixture");
    let request = &fixture["request"];
    let body = serde_json::to_vec(&request["body"]).expect("Compact request JSON");

    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let (websocket_address, websocket_task) = spawn_websocket_upstream().await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let response = send_json_request(
        &proxy,
        request["path"].as_str().expect("Compact path"),
        "",
        &body,
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let response_body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("Compact HTTP response body");
    let expected_response = fixture["provider_response_wire"]
        .as_str()
        .expect("Compact response wire fixture");
    assert_eq!(response_body.as_bytes(), expected_response.as_bytes());

    for (case, invalid_body) in [
        ("missing model", br#"{"input":"missing model"}"#.as_slice()),
        (
            "empty model",
            br#"{"model":"","input":"invalid"}"#.as_slice(),
        ),
        (
            "non-string model",
            br#"{"model":7,"input":"invalid"}"#.as_slice(),
        ),
        ("malformed JSON", b"{".as_slice()),
    ] {
        let rejected = send_json_request(
            &proxy,
            request["path"].as_str().expect("Compact path"),
            "",
            invalid_body,
        )
        .await;
        assert!(rejected.starts_with("HTTP/1.1 400"), "{case}: {rejected}");
    }

    const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
    let prefix = b"{\"model\":\"gpt-4o\",\"input\":\"";
    let suffix = b"\"}";
    let mut exact_limit = Vec::with_capacity(MAX_BODY_BYTES);
    exact_limit.extend_from_slice(prefix);
    exact_limit.resize(MAX_BODY_BYTES - suffix.len(), b'a');
    exact_limit.extend_from_slice(suffix);
    assert_eq!(exact_limit.len(), MAX_BODY_BYTES);
    let exact_limit_response = send_json_request(
        &proxy,
        request["path"].as_str().expect("Compact path"),
        "",
        &exact_limit,
    )
    .await;
    assert!(
        exact_limit_response.starts_with("HTTP/1.1 200"),
        "exact limit: {exact_limit_response}"
    );

    let over_limit = vec![b'x'; MAX_BODY_BYTES + 1];
    let over_limit_response = send_json_request(
        &proxy,
        request["path"].as_str().expect("Compact path"),
        "",
        &over_limit,
    )
    .await;
    assert!(
        over_limit_response.starts_with("HTTP/1.1 413"),
        "over limit: {over_limit_response}"
    );

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let log = upstream.finish().await;
    websocket_task.abort();

    log.assert_accepted_everything();
    let compact_requests: Vec<_> = log
        .accepted
        .iter()
        .filter(|request| request.path == "/v1/responses/compact")
        .collect();
    assert_eq!(
        compact_requests.len(),
        2,
        "invalid and over-limit Compact input stayed local"
    );
    let observed = compact_requests[0];
    assert_eq!(observed.method, request["method"].as_str().unwrap());
    assert_eq!(observed.query, None);
    assert_eq!(
        observed.header("authorization"),
        Some("Bearer gateway-test-key")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&observed.body).expect("upstream Compact JSON"),
        request["body"]
    );
    assert_eq!(compact_requests[1].body.len(), MAX_BODY_BYTES);
}

#[tokio::test]
async fn the_gateway_preset_uses_semantic_responses_websocket_with_continuation() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/openai/responses-websocket-semantic-2026-08-21.json");
    let fixture: Value =
        serde_json::from_str(MANIFEST_FIXTURE).expect("semantic Responses fixture");
    let downstream_turns = fixture["downstream_turns"]
        .as_array()
        .expect("downstream fixture turns")
        .clone();
    let provider_turns = fixture["provider_turns"]
        .as_array()
        .expect("provider fixture turns")
        .iter()
        .map(|turn| turn.as_array().expect("provider events").clone())
        .collect();

    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let (websocket_address, websocket_task) =
        spawn_semantic_responses_upstream(provider_turns).await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let first_body = serde_json::to_vec(&downstream_turns[0]).expect("first request JSON");
    let first_response = send_responses_request(&proxy, &first_body).await;
    assert!(
        first_response.starts_with("HTTP/1.1 200"),
        "{first_response}"
    );
    assert!(
        first_response.contains("response.function_call_arguments.delta"),
        "tool event must survive semantic transport: {first_response}"
    );
    assert!(
        first_response.contains("\"total_tokens\":13"),
        "terminal usage must survive semantic transport: {first_response}"
    );

    let second_body = serde_json::to_vec(&downstream_turns[1]).expect("second request JSON");
    let second_response = send_responses_request(&proxy, &second_body).await;
    assert!(
        second_response.contains("response.output_text.delta") && second_response.contains("Sunny"),
        "second semantic turn must complete: {second_response}"
    );

    let (authorized, first, second) = websocket_task.await.expect("semantic websocket task");
    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let log = upstream.finish().await;

    log.assert_accepted_everything();
    assert!(
        authorized,
        "Pooler must place OpenAI authentication and beta headers"
    );
    assert_eq!(first["type"], "response.create");
    assert_eq!(first["store"], false);
    assert_eq!(first["stream"], true);
    assert_eq!(first["tools"][0]["name"], "weather");
    assert_eq!(first["reasoning"]["effort"], "high");
    assert_eq!(second["type"], "response.create");
    assert_eq!(
        second["previous_response_id"], fixture["expected_second_upstream"]["previous_response_id"],
        "{second}"
    );
    let expected_types = fixture["expected_second_upstream"]["input_types"]
        .as_array()
        .expect("expected input types");
    let actual_types: Vec<&Value> = second["input"]
        .as_array()
        .expect("continuation delta input")
        .iter()
        .map(|item| &item["type"])
        .collect();
    assert_eq!(actual_types, expected_types.iter().collect::<Vec<_>>());
}

#[tokio::test]
async fn the_gateway_preset_validates_openai_realtime_lifecycle() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/openai/realtime-websocket-2026-08-22.json");
    let fixture: Value = serde_json::from_str(MANIFEST_FIXTURE).expect("OpenAI Realtime fixture");
    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let (websocket_address, websocket_task) = spawn_openai_realtime_upstream().await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut request = format!(
        "ws://{proxy}{}",
        fixture["handshake"]["path"]
            .as_str()
            .expect("Realtime path")
    )
    .into_client_request()
    .expect("Realtime client request");
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static("realtime, openai-insecure-api-key.downstream-sentinel"),
    );
    let (mut client, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("gateway accepts Realtime WebSocket");
    assert_eq!(
        response.headers().get("sec-websocket-protocol"),
        Some(&HeaderValue::from_static("realtime"))
    );
    let session_created: Value = serde_json::from_str(
        &client
            .next()
            .await
            .expect("session.created")
            .expect("session.created message")
            .into_text()
            .expect("session.created text"),
    )
    .expect("session.created JSON");
    assert_eq!(session_created, fixture["server_events"][0]);

    for event in fixture["client_events"]
        .as_array()
        .expect("Realtime client events")[..4]
        .iter()
    {
        client
            .send(Message::Text(event.to_string().into()))
            .await
            .expect("Realtime client event");
    }

    let mut provider_events = Vec::new();
    for _ in 0..3 {
        let event: Value = serde_json::from_str(
            &client
                .next()
                .await
                .expect("Realtime provider event")
                .expect("Realtime provider message")
                .into_text()
                .expect("Realtime provider text"),
        )
        .expect("Realtime provider JSON");
        provider_events.push(event);
    }
    assert_eq!(
        provider_events.as_slice(),
        &fixture["server_events"]
            .as_array()
            .expect("Realtime server events")[1..4]
    );

    for event in fixture["client_events"]
        .as_array()
        .expect("Realtime client events")[4..]
        .iter()
    {
        client
            .send(Message::Text(event.to_string().into()))
            .await
            .expect("Realtime interruption event");
    }
    let done: Value = serde_json::from_str(
        &client
            .next()
            .await
            .expect("response.done")
            .expect("response.done message")
            .into_text()
            .expect("response.done text"),
    )
    .expect("response.done JSON");
    assert_eq!(done, fixture["server_events"][4]);
    let _ = client.close(None).await;

    let (path, authorized, protocols, client_events) =
        websocket_task.await.expect("Realtime upstream task");
    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let log = upstream.finish().await;

    log.assert_accepted_everything();
    assert_eq!(path, fixture["handshake"]["path"]);
    assert!(
        authorized,
        "Pooler must inject the selected OpenAI credential"
    );
    assert_eq!(protocols, ["realtime"]);
    assert_eq!(
        client_events.as_slice(),
        fixture["client_events"]
            .as_array()
            .expect("Realtime client events")
            .as_slice()
    );
    assert!(client_events
        .iter()
        .any(|event| event["type"] == "input_audio_buffer.append"));
    assert!(client_events
        .iter()
        .any(|event| event["type"] == "response.cancel"));
    assert!(client_events
        .iter()
        .any(|event| event["type"] == "output_audio_buffer.clear"));
}

#[tokio::test]
async fn openai_realtime_sideband_reuses_the_call_id_websocket_route() {
    const FIXTURE: &str = include_str!("../../../fixtures/openai/realtime-control-2026-08-22.json");
    let fixture: Value = serde_json::from_str(FIXTURE).expect("Realtime control fixture");
    let expected_path = fixture["sideband_handshake"]["path"]
        .as_str()
        .expect("sideband path");
    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let (websocket_address, websocket_task) = spawn_openai_sideband_upstream().await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut request = format!("ws://{proxy}{expected_path}")
        .into_client_request()
        .expect("sideband request");
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static("realtime, openai-insecure-api-key.downstream-sentinel"),
    );
    let (mut client, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("gateway accepts sideband connection");
    assert_eq!(response.status(), 101);
    assert_eq!(
        response.headers().get("sec-websocket-protocol"),
        Some(&HeaderValue::from_static("realtime"))
    );
    let created: Value = serde_json::from_str(
        &client
            .next()
            .await
            .expect("sideband session.created")
            .expect("sideband session.created message")
            .into_text()
            .expect("sideband session.created text"),
    )
    .expect("sideband session.created JSON");
    assert_eq!(created["type"], "session.created");
    client.close(None).await.expect("close sideband connection");

    let (path, authorized, protocols) = websocket_task.await.expect("sideband upstream task");
    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    upstream.finish().await.assert_accepted_everything();

    assert_eq!(path, expected_path);
    assert!(
        authorized,
        "Pooler must inject the selected OpenAI credential"
    );
    assert_eq!(protocols, ["realtime"]);
}

#[tokio::test]
async fn openai_realtime_rejects_invalid_client_events_before_upstream_delivery() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Realtime boundary upstream bind");
    let websocket_address = listener.local_addr().expect("Realtime boundary address");
    let websocket_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("Realtime boundary accepts");
        let mut socket = accept_async(stream)
            .await
            .expect("Realtime boundary handshake");
        socket
            .send(Message::Text(
                r#"{"type":"session.created","event_id":"evt_session","session":{"id":"sess_1"}}"#
                    .into(),
            ))
            .await
            .expect("boundary session.created");
        while let Some(message) = socket.next().await {
            match message.expect("boundary upstream message") {
                Message::Text(_) | Message::Binary(_) => return true,
                Message::Close(_) => return false,
                Message::Ping(payload) => {
                    socket
                        .send(Message::Pong(payload))
                        .await
                        .expect("boundary pong");
                }
                Message::Pong(_) | Message::Frame(_) => {}
            }
        }
        false
    });

    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let (mut client, _) =
        tokio_tungstenite::connect_async(format!("ws://{proxy}/v1/realtime?model=gpt-realtime"))
            .await
            .expect("Realtime boundary WebSocket");
    let _ = client.next().await.expect("boundary session.created");
    client
        .send(Message::Text(
            r#"{"type":"undocumented.realtime.event"}"#.into(),
        ))
        .await
        .expect("send invalid Realtime event");
    let close = match client
        .next()
        .await
        .expect("policy close")
        .expect("policy close message")
    {
        Message::Close(Some(close)) => close,
        other => panic!("expected policy close, got {other:?}"),
    };
    assert_eq!(
        close.code,
        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy
    );
    assert!(
        !websocket_task.await.expect("boundary upstream task"),
        "invalid event must not reach the provider"
    );

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    upstream.finish().await.assert_accepted_everything();
}

#[tokio::test]
async fn the_gateway_preset_tunnels_a_responses_websocket() {
    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let (websocket_address, websocket_task) = spawn_websocket_upstream().await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{proxy}/v1/responses"))
        .await
        .expect("gateway accepts the WebSocket upgrade");
    client
        .send(Message::Text("hello".into()))
        .await
        .expect("client sends");
    let echoed = client.next().await.expect("echo").expect("echo message");
    client.close(None).await.expect("client closes");

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let log = upstream.finish().await;
    let observed = websocket_task.await.expect("websocket upstream task");

    log.assert_accepted_everything();
    assert_eq!(echoed.into_text().expect("text echo").as_str(), "hello");
    assert_eq!(
        observed,
        vec!["hello".to_owned()],
        "the frame must reach the WebSocket upstream"
    );
}
