//! Native Palantir AIP route-contract tests.

use http::HeaderMap;
use pooler_config::compile_yaml;
use pooler_http::PoolingCoordinator;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[path = "support/sse_provider.rs"]
mod sse_provider;

const RID: &str = "ri.language-model-service..language-model.anthropic-claude-4-6-opus";

#[tokio::test]
async fn strict_sse_support_preserves_event_bytes() {
    let provider =
        sse_provider::SseProvider::start(b"data: {\"ok\":true}\n\n", "text/event-stream").await;
    let mut client = TcpStream::connect(provider.address())
        .await
        .expect("strict SSE provider");
    client
        .write_all(
            b"POST /api/v2/llm/proxy/openai/v1/responses HTTP/1.1\r\nhost: enrollment\r\ncontent-length: 2\r\n\r\n{}",
        )
        .await
        .expect("strict SSE request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("SSE response");
    let requests = provider.finish().await;
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/api/v2/llm/proxy/openai/v1/responses");
    assert!(String::from_utf8_lossy(&response).contains("data: {\"ok\":true}\n\n"));
}

fn palantir_config(model: &str) -> String {
    format!(
        r#"
version: 2
listeners:
  gateway: {{bind: 127.0.0.1:0}}
upstreams:
  palantir:
    url: https://example.euw-3.palantirfoundry.co.uk
    native: {{kind: palantir_aip}}
    oauth:
      client_id: test-client
      grant_type: client_credentials
      client_secret: env:PALANTIR_CLIENT_SECRET
      scopes: [api:use-language-models-execute]
accounts:
  palantir-account: {{provider: palantir, auth_kind: oauth}}
account_pools:
  palantir-pool: {{provider: palantir, accounts: [palantir-account]}}
models:
  - id: public-model
    targets:
      - id: palantir-target
        provider: palantir
        account_pool: palantir-pool
        priority: 1
        upstream_model: {model}
        capabilities: [text, streaming]
        codecs: [openai]
        wire_family: openai
routes:
  - id: chat
    listen: gateway
    match: {{method: POST, path: /v1/chat/completions}}
    target: {{provider: palantir, path: /api/v2/llm/proxy/openai/v1/chat/completions}}
    ingress: {{mode: opaque}}
    response: {{mode: opaque}}
  - id: responses
    listen: gateway
    match: {{method: POST, path: /v1/responses}}
    target: {{provider: palantir, path: /api/v2/llm/proxy/openai/v1/responses}}
    ingress: {{mode: opaque}}
    response: {{mode: opaque}}
  - id: messages
    listen: gateway
    match: {{method: POST, path: /v1/messages}}
    target: {{provider: palantir, path: /api/v2/llm/proxy/anthropic/v1/messages}}
    ingress: {{mode: opaque}}
    response: {{mode: opaque}}
"#
    )
}

#[test]
fn palantir_model_rid_is_explicit_and_valid() {
    compile_yaml("palantir-valid.yaml", &palantir_config(RID)).expect("valid RID compiles");
    for invalid in [
        "claude-4",
        "ri.language-model-service..language-model.",
        "ri.language-model-service..language-model.bad/model",
    ] {
        let error = compile_yaml("palantir-invalid.yaml", &palantir_config(invalid))
            .expect_err("invalid RID must fail before serving");
        assert!(error.to_string().contains("explicit valid model RID"));
    }
}

#[test]
fn palantir_routes_are_exact_same_origin_paths() {
    let config = compile_yaml("palantir-routes.yaml", &palantir_config(RID))
        .expect("Palantir route contract");
    assert_eq!(
        config.routes()[0].target().path(),
        Some("/api/v2/llm/proxy/openai/v1/chat/completions")
    );
    assert_eq!(
        config.routes()[1].target().path(),
        Some("/api/v2/llm/proxy/openai/v1/responses")
    );
    assert_eq!(
        config.routes()[2].target().path(),
        Some("/api/v2/llm/proxy/anthropic/v1/messages")
    );
    assert_eq!(config.upstreams()["palantir"].url().path(), "/");
}

#[test]
fn selected_provider_upstream_uri_is_authoritative() {
    let yaml = r#"
version: 2
listeners: {gateway: {bind: 127.0.0.1:0}}
upstreams:
  anchor: {url: http://127.0.0.1:8319/anchor}
  selected: {url: http://127.0.0.1:8320/selected?tenant=selected}
accounts:
  anchor-account: {provider: anchor, secret: env:POOLER_ANCHOR_KEY}
  selected-account: {provider: selected, secret: env:POOLER_SELECTED_KEY}
models:
  - id: public-model
    targets:
      - {id: anchor-target, provider: anchor, account: anchor-account, priority: 1, upstream_model: anchor-model, capabilities: [text], codecs: [], wire_family: openai}
      - {id: selected-target, provider: selected, account: selected-account, priority: 2, upstream_model: selected-model, capabilities: [text], codecs: [], wire_family: openai}
policies:
  fallback: {selection: {strategy: ordered_fallback}}
routes:
  - id: route
    listen: gateway
    match: {method: POST, path: /v1/chat/completions}
    target: {provider: anchor, path: /api/v2/llm/proxy/openai/v1/chat/completions, model_from: request.model, policy: fallback}
    ingress: {mode: patch}
    response: {mode: opaque}
"#;
    let config = compile_yaml("selected-uri.yaml", yaml).expect("selected URI config");
    let route = config.route("route").expect("route");
    let coordinator = PoolingCoordinator::new(&config).expect("pool coordinator");
    coordinator
        .set_account_enabled("anchor-account", false)
        .expect("disable anchor");
    let selection = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &HeaderMap::new(),
            1,
            Instant::now(),
        )
        .expect("selected provider");
    let uri = selection
        .upstream_uri(
            &config,
            route,
            &"/v1/chat/completions?stream=true".parse().unwrap(),
        )
        .expect("selected provider URI");
    assert_eq!(
        uri,
        "http://127.0.0.1:8320/v1/chat/completions?tenant=selected&stream=true"
    );
    assert!(!uri.to_string().contains("8319"));
}
