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
    tungstenite::{handshake::server::Request, Message},
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

async fn send_responses_request(proxy: &str, body: &[u8]) -> String {
    let mut downstream = TcpStream::connect(proxy).await.expect("proxy connection");
    downstream
        .write_all(
            format!(
                "POST /v1/responses HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\nsession-id: mounted-session\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("Responses request headers");
    downstream
        .write_all(body)
        .await
        .expect("Responses request body");
    let mut response = Vec::new();
    downstream
        .read_to_end(&mut response)
        .await
        .expect("Responses response");
    String::from_utf8(response).expect("Responses response UTF-8")
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
