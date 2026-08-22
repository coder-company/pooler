//! Wire-level provider conformance for the gateway preset.
//!
//! Every request here is judged by a strict provider fake that enforces what
//! the real endpoint accepts: path, method, credential placement, required
//! headers, query shape, content type, and body shape. A request the real
//! provider would refuse fails the test rather than passing because the fake
//! was generous.
//!
//! A preset supplies the operator's protected credential reference. Where that
//! credential belongs is the provider's documented fact.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use pooler_auth::MemoryOAuthTokenStore;
use pooler_http::NativeRuntime;
use pooler_server::HttpProxyServer;
use pooler_testkit::{ProviderContract, ProviderLog, StrictProvider};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SECRET: &str = "operator-chosen-key";

fn gateway_config(
    directory: &TempDir,
    provider: &str,
    upstream: SocketAddr,
) -> pooler_config::CompiledConfig {
    // `NamedTempFile` creates the file owner-only, which the secret loader
    // requires, and a file reference keeps the fixture deterministic under a
    // parallel suite where a process-global environment variable would not be.
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
            "imports:\n  - preset: gateway\n    as: gw\n    with:\n      bind: 127.0.0.1:0\n      provider: {provider}\n      upstream_url: http://{upstream}\n      websocket_url: ws://{upstream}\n      secret: 'file:{secret}'\n\nversion: 1\n"
        ),
    )
    .expect("gateway config");
    pooler_config::Config::from_path(&path)
        .expect("gateway loads")
        .compile()
        .expect("gateway compiles")
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

/// One request a client sends through the gateway.
struct Call<'a> {
    method: &'a str,
    path: &'a str,
    content_type: Option<&'a str>,
    body: &'a [u8],
    extra_headers: &'a str,
}

/// Drive calls through a gateway bound to `provider` and return what the strict
/// provider observed, plus each downstream response.
async fn exchange(
    contract: ProviderContract,
    provider: &str,
    calls: &[Call<'_>],
) -> (ProviderLog, Vec<String>) {
    let upstream = StrictProvider::start(contract, SECRET).await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, provider, upstream.address());
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut responses = Vec::new();
    for call in calls {
        let mut downstream = TcpStream::connect(&proxy).await.expect("proxy connection");
        let content_type = call
            .content_type
            .map(|value| format!("content-type: {value}\r\n"))
            .unwrap_or_default();
        downstream
            .write_all(
                format!(
                    "{} {} HTTP/1.1\r\nhost: localhost\r\n{content_type}{}content-length: {}\r\nconnection: close\r\n\r\n",
                    call.method,
                    call.path,
                    call.extra_headers,
                    call.body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("downstream headers");
        downstream
            .write_all(call.body)
            .await
            .expect("downstream body");
        let mut response = Vec::new();
        downstream
            .read_to_end(&mut response)
            .await
            .expect("downstream response");
        responses.push(String::from_utf8_lossy(&response).to_string());
    }

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    (upstream.finish().await, responses)
}

fn get(path: &str) -> Call<'_> {
    Call {
        method: "GET",
        path,
        content_type: None,
        body: b"",
        extra_headers: "",
    }
}

fn post<'a>(path: &'a str, body: &'a [u8]) -> Call<'a> {
    Call {
        method: "POST",
        path,
        content_type: Some("application/json"),
        body,
        extra_headers: "",
    }
}

fn call_without_body<'a>(method: &'a str, path: &'a str) -> Call<'a> {
    Call {
        method,
        path,
        content_type: None,
        body: b"",
        extra_headers: "",
    }
}

fn assert_all_accepted(log: &ProviderLog, responses: &[String]) {
    log.assert_accepted_everything();
    for response in responses {
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "the gateway must return the provider's success: {response}"
        );
    }
}

#[tokio::test]
async fn openai_routes_satisfy_a_strict_openai_endpoint() {
    let (log, responses) = exchange(
        ProviderContract::openai(),
        "openai",
        &[
            get("/v1/models"),
            post(
                "/v1/chat/completions",
                br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
            ),
            post(
                "/v1/responses/compact",
                br#"{"model":"gpt-4o","input":"sanitized"}"#,
            ),
        ],
    )
    .await;

    assert_all_accepted(&log, &responses);
    let chat = log
        .accepted_for("/v1/chat/completions")
        .expect("chat reached the upstream");
    assert_eq!(
        chat.header("authorization"),
        Some(format!("Bearer {SECRET}").as_str())
    );
}

#[tokio::test]
async fn openai_realtime_control_routes_match_the_sdk_wire_contract() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/openai/realtime-control-2026-08-22.json");
    let fixture: serde_json::Value =
        serde_json::from_str(MANIFEST_FIXTURE).expect("OpenAI Realtime control fixture");
    let requests = fixture["requests"].as_array().expect("fixture requests");
    let bodies = requests
        .iter()
        .map(|request| {
            request
                .get("body")
                .map(|body| serde_json::to_vec(body).expect("fixture body JSON"))
        })
        .collect::<Vec<_>>();
    let extra_headers = requests
        .iter()
        .map(|request| {
            let mut headers = String::from("authorization: Bearer downstream-sentinel\r\n");
            for (name, value) in request["headers"].as_object().expect("fixture headers") {
                headers.push_str(name);
                headers.push_str(": ");
                headers.push_str(value.as_str().expect("fixture header value"));
                headers.push_str("\r\n");
            }
            headers
        })
        .collect::<Vec<_>>();
    let calls = requests
        .iter()
        .zip(&bodies)
        .zip(&extra_headers)
        .map(|((request, body), headers)| Call {
            method: request["method"].as_str().expect("fixture method"),
            path: request["path"].as_str().expect("fixture path"),
            content_type: body.as_ref().map(|_| "application/json"),
            body: body.as_deref().unwrap_or_default(),
            extra_headers: headers,
        })
        .collect::<Vec<_>>();

    let (log, responses) = exchange(ProviderContract::openai(), "openai", &calls).await;

    assert_all_accepted(&log, &responses);
    let observed_requests = log
        .accepted
        .iter()
        .filter(|request| request.path.starts_with("/v1/realtime/"))
        .collect::<Vec<_>>();
    assert_eq!(observed_requests.len(), requests.len());
    for ((observed, expected), response) in
        observed_requests.into_iter().zip(requests).zip(&responses)
    {
        assert_eq!(
            observed.method,
            expected["method"].as_str().expect("fixture method")
        );
        assert_eq!(
            observed.path,
            expected["path"].as_str().expect("fixture path")
        );
        assert_eq!(observed.query, None);
        assert_eq!(
            observed.header("authorization"),
            Some(format!("Bearer {SECRET}").as_str())
        );
        if let Some(body) = expected.get("body") {
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&observed.body)
                    .expect("upstream body JSON"),
                *body
            );
        } else {
            assert!(observed.body.is_empty());
        }

        let response_body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("downstream response body");
        let name = expected["name"].as_str().expect("fixture request name");
        if let Some(expected_response) = fixture["provider_responses"].get(name) {
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(response_body)
                    .expect("downstream response JSON"),
                *expected_response
            );
        } else {
            assert!(response_body.is_empty(), "{name}: {response_body}");
        }
    }
}

#[tokio::test]
async fn xai_responses_compact_satisfies_the_strict_xai_endpoint() {
    let (log, responses) = exchange(
        ProviderContract::xai(),
        "xai",
        &[post(
            "/v1/responses/compact",
            br#"{"model":"grok-4.1-fast","input":"sanitized"}"#,
        )],
    )
    .await;

    assert_all_accepted(&log, &responses);
    let compact = log
        .accepted_for("/v1/responses/compact")
        .expect("xAI Compact reached the upstream");
    assert_eq!(
        compact.header("authorization"),
        Some(format!("Bearer {SECRET}").as_str())
    );
}

#[tokio::test]
async fn anthropic_routes_satisfy_a_strict_anthropic_endpoint() {
    let (log, responses) = exchange(
        ProviderContract::anthropic(),
        "anthropic",
        &[
            get("/v1/models"),
            post(
                "/v1/messages",
                br#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}"#,
            ),
            post(
                "/v1/messages/count_tokens",
                br#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}"#,
            ),
        ],
    )
    .await;

    assert_all_accepted(&log, &responses);
    let messages = log
        .accepted_for("/v1/messages")
        .expect("messages reached the upstream");
    assert_eq!(messages.header("x-api-key"), Some(SECRET));
    assert_eq!(messages.header("anthropic-version"), Some("2023-06-01"));
}

#[tokio::test]
async fn gemini_routes_satisfy_a_strict_gemini_endpoint() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/gemini/gateway-same-wire-2026-08-21.json");
    let fixture: serde_json::Value =
        serde_json::from_str(MANIFEST_FIXTURE).expect("Gemini compatibility fixture");
    let requests = fixture["requests"].as_array().expect("fixture requests");
    let bodies = requests
        .iter()
        .map(|request| {
            request["body"]
                .is_object()
                .then(|| serde_json::to_vec(&request["body"]).expect("fixture body JSON"))
        })
        .collect::<Vec<_>>();
    let calls = requests
        .iter()
        .zip(&bodies)
        .map(|(request, body)| Call {
            method: request["method"].as_str().expect("fixture method"),
            path: request["path"].as_str().expect("fixture path"),
            content_type: body.as_ref().map(|_| "application/json"),
            body: body.as_deref().unwrap_or_default(),
            extra_headers: "",
        })
        .collect::<Vec<_>>();
    let (log, responses) = exchange(ProviderContract::gemini(), "google", &calls).await;

    log.assert_accepted_everything();
    for (index, response) in responses.iter().enumerate() {
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "Gemini call {index} must return the provider's success: {response}"
        );
    }
    let generate = log
        .accepted_for("/v1beta/models/gemini-2.5-pro:generateContent")
        .expect("generateContent reached the upstream");
    assert_eq!(generate.header("x-goog-api-key"), Some(SECRET));
}

#[tokio::test]
async fn gemini_gateway_rejects_unknown_actions_and_encoded_model_separators_locally() {
    let (log, responses) = exchange(
        ProviderContract::gemini(),
        "google",
        &[
            post(
                "/v1beta/models/gemini-2.5-pro:unknownAction",
                br#"{"contents":[{"parts":[{"text":"hi"}]}]}"#,
            ),
            post(
                "/v1beta/models/team%2Fgemini:countTokens",
                br#"{"contents":[{"parts":[{"text":"hi"}]}]}"#,
            ),
            call_without_body("POST", "/v1beta/interactions/int_wrong_method"),
            call_without_body("DELETE", "/v1beta/interactions/int_wrong_method/cancel"),
        ],
    )
    .await;

    log.assert_accepted_everything();
    assert!(
        log.accepted.iter().all(|request| {
            !request.path.contains("unknownAction") && !request.path.contains("team%2Fgemini")
        }),
        "invalid Gemini paths must never reach the provider: {:?}",
        log.accepted
    );
    for response in responses {
        assert!(
            response.starts_with("HTTP/1.1 400") || response.starts_with("HTTP/1.1 405"),
            "invalid Gemini path or method must be a local client error: {response}"
        );
    }
}

/// A caller must never smuggle a provider credential through the gateway. The
/// strict fake refuses any foreign credential header, so this fails loudly if
/// the caller's headers survive.
#[tokio::test]
async fn client_supplied_credential_headers_never_reach_any_provider() {
    const SENTINELS: &str = "authorization: Bearer client-sentinel\r\nx-api-key: client-sentinel\r\nx-goog-api-key: client-sentinel\r\n";

    let cases: [(ProviderContract, &str, &str, &[u8]); 3] = [
        (
            ProviderContract::openai(),
            "openai",
            "/v1/chat/completions",
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        ),
        (
            ProviderContract::anthropic(),
            "anthropic",
            "/v1/messages",
            br#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}"#,
        ),
        (
            ProviderContract::gemini(),
            "google",
            "/v1beta/models/gemini-2.5-pro:generateContent",
            br#"{"contents":[{"parts":[{"text":"hi"}]}]}"#,
        ),
    ];

    for (contract, provider, path, body) in cases {
        let (log, responses) = exchange(
            contract,
            provider,
            &[Call {
                method: "POST",
                path,
                content_type: Some("application/json"),
                body,
                extra_headers: SENTINELS,
            }],
        )
        .await;
        assert_all_accepted(&log, &responses);
    }
}

/// The strict fake must actually be strict: a request the provider does not
/// serve is refused, so these tests cannot pass by accident.
#[tokio::test]
async fn the_strict_provider_refuses_a_request_the_endpoint_does_not_serve() {
    let upstream = StrictProvider::start(ProviderContract::anthropic(), SECRET).await;
    let address = upstream.address();

    // Talk to the fake directly: a wrong path, a missing version header, and a
    // foreign credential header must each be refused.
    for (request, expected) in [
        (
            format!("GET /v1/chat/completions HTTP/1.1\r\nhost: x\r\nx-api-key: {SECRET}\r\nanthropic-version: 2023-06-01\r\nconnection: close\r\n\r\n"),
            "404",
        ),
        (
            format!("GET /v1/models HTTP/1.1\r\nhost: x\r\nx-api-key: {SECRET}\r\nconnection: close\r\n\r\n"),
            "400",
        ),
        (
            format!("GET /v1/models HTTP/1.1\r\nhost: x\r\nx-api-key: {SECRET}\r\nanthropic-version: 2023-06-01\r\nauthorization: Bearer smuggled\r\nconnection: close\r\n\r\n"),
            "401",
        ),
    ] {
        let mut stream = TcpStream::connect(address).await.expect("fake connection");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("fake request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("fake response");
        let response = String::from_utf8_lossy(&response).to_string();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected}")),
            "expected {expected}, got: {response}"
        );
    }

    let log = upstream.finish().await;
    assert_eq!(log.accepted.len(), 0, "{:?}", log.accepted);
    assert_eq!(log.rejected.len(), 3, "{:?}", log.rejected);
}

/// The secret must not appear in rendered configuration.
#[test]
fn the_credential_value_is_never_rendered() {
    let directory = TempDir::new().expect("config directory");
    let path = directory.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "imports:\n  - preset: gateway\n    as: gw\n    with: {bind: 127.0.0.1:0, provider: anthropic, secret: 'env:OPERATOR_KEY'}\n\nversion: 1\n",
    )
    .expect("gateway config");

    let rendered = pooler_config::render_path(&path).expect("rendered gateway");
    assert!(rendered.contains("env:OPERATOR_KEY"));
    assert!(!rendered.contains(SECRET));
}

/// The upstream credential must not reach any management surface.
///
/// `/export` redaction for account and mutation secrets is covered inside
/// `management.rs`. This closes the remaining case: the credential a preset
/// supplies for its upstream, observed after a real request has flowed, across
/// every read endpoint an operator can reach.
#[tokio::test]
async fn the_upstream_credential_never_reaches_a_management_surface() {
    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let directory = TempDir::new().expect("config directory");

    let mut secret_file = tempfile::NamedTempFile::new_in(directory.path()).expect("secret file");
    secret_file
        .write_all(SECRET.as_bytes())
        .expect("secret contents");
    let (_, secret) = secret_file.keep().expect("secret persists");
    let secret_reference = format!("file:{}", secret.display());
    let path = directory.path().join("gateway.yaml");
    std::fs::write(
        &path,
        format!(
            "imports:\n  - preset: gateway\n    as: gw\n    with:\n      bind: 127.0.0.1:0\n      upstream_url: http://{}\n      secret: '{secret_reference}'\n\nversion: 1\nmanagement: {{bind: 127.0.0.1:0}}\n",
            upstream.address()
        ),
    )
    .expect("gateway config");
    let config = pooler_config::Config::from_path(&path)
        .expect("gateway loads")
        .compile()
        .expect("gateway compiles");

    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let management = server
        .management_address()
        .expect("management address")
        .to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    // Drive a real request so decisions, traces, and metrics are populated.
    let body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
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
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

    let surfaces = [
        "/health",
        "/listeners",
        "/routes",
        "/models",
        "/catalog",
        "/accounts",
        "/health/providers",
        "/quota",
        "/metrics",
        "/decisions",
        "/traces",
        "/audit",
        "/reloads",
        "/export",
    ];
    let mut seen = Vec::new();
    for surface in surfaces {
        let mut stream = TcpStream::connect(&management)
            .await
            .expect("management connection");
        stream
            .write_all(
                format!("GET {surface} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("management request");
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .await
            .expect("management response");
        seen.push((surface, String::from_utf8_lossy(&bytes).to_string()));
    }

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let log = upstream.finish().await;
    log.assert_accepted_everything();

    for (surface, body) in &seen {
        // Guard against a vacuous pass: a surface that 404s or returns nothing
        // proves no redaction.
        assert!(
            body.starts_with("HTTP/1.1 200"),
            "{surface} must be reachable to prove anything: {body}"
        );
        assert!(
            body.len() > 64,
            "{surface} returned no meaningful body: {body}"
        );
        assert!(
            !body.contains(SECRET),
            "{surface} leaked the credential value"
        );
        // A secret reference is a path to owner-private material; it is not a
        // credential, but it must not be published either.
        assert!(
            !body.contains(&secret_reference),
            "{surface} leaked the secret reference"
        );
    }
}
