use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use http::{HeaderMap, Method, StatusCode};
use pooler_http::PoolingCoordinator;
use pooler_model_catalog::{DiscoveryFailure, DiscoveryFailureKind};
use pooler_server::{
    ActiveCounts, CatalogFetchFuture, CatalogFetcherRegistration, CatalogRuntime, FetchedCatalog,
    HttpProxyServer, ManagementApi, ProviderCatalogFetcher,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug)]
struct FakeProvider {
    responses: Mutex<VecDeque<Result<FetchedCatalog, DiscoveryFailure>>>,
}

impl FakeProvider {
    fn new(responses: impl IntoIterator<Item = Result<FetchedCatalog, DiscoveryFailure>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

impl ProviderCatalogFetcher for FakeProvider {
    fn fetch(&self, _max_response_bytes: usize) -> CatalogFetchFuture<'_> {
        let response = self
            .responses
            .lock()
            .expect("fake provider lock")
            .pop_front()
            .expect("fake response available");
        Box::pin(std::future::ready(response))
    }
}

fn config() -> pooler_config::CompiledConfig {
    pooler_config::compile_yaml(
        "catalog-runtime.yaml",
        r#"
version: 1
management: {bind: 127.0.0.1:0}
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {provider-a: {url: http://127.0.0.1:1}}
models:
  - id: configured-only
    targets: [{provider: provider-a, upstream_model: configured-upstream, capabilities: [text]}]
catalog:
  refresh: {timeout_ms: 1000, max_models_per_source: 10, max_total_models: 10}
  sources:
    - id: provider-a.primary
      provider: provider-a
      parser: kimi
      prefix: team
      included_models: ['model-*']
      excluded_models: ['*-old']
      aliases:
        - {name: model-live, alias: best, force_mapping: true, display_name: Best Model}
routes:
  - id: route
    listen: local
    ingress: {mode: patch}
    target: {provider: provider-a, model_from: request.model}
"#,
    )
    .expect("catalog runtime config")
}

#[tokio::test]
async fn fake_provider_snapshot_drives_cli_management_shape_and_retains_last_good() {
    const SECRET_SENTINEL: &str = "catalog-provider-secret-sentinel";
    let config = config();
    let provider = Arc::new(FakeProvider::new([
        Ok(FetchedCatalog::new(
            br#"{"data":[
              {"id":"model-live","display_name":"Live"},
              {"id":"model-old"},
              {"id":"internal"}
            ]}"#
            .as_slice(),
            Some("fixture-revision".to_owned()),
        )),
        Err(DiscoveryFailure::new(SECRET_SENTINEL)),
    ]));
    let runtime = Arc::new(
        CatalogRuntime::with_fetchers(
            config.catalog().expect("catalog plan").clone(),
            vec![
                CatalogFetcherRegistration::new("provider-a.primary", provider)
                    .expect("registration"),
            ],
        )
        .expect("runtime"),
    );
    runtime.refresh().await.expect("first refresh");
    let first = runtime.snapshot();
    assert_eq!(first.generation(), 1);
    assert!(first.get("team/best").is_some());
    assert!(
        first.get("team/model-live").is_none(),
        "rename is not a fork"
    );
    assert!(first.get("team/model-old").is_none(), "exclusion applies");
    assert!(first.get("team/internal").is_none(), "allow-list applies");

    let error = runtime.refresh().await.expect_err("second refresh fails");
    assert_eq!(
        error.to_string(),
        "model discovery from provider-a.primary failed (provider)"
    );
    assert!(!error.to_string().contains(SECRET_SENTINEL));
    assert_eq!(
        &*runtime.snapshot(),
        &*first,
        "last good snapshot stays live"
    );

    let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling"));
    let api = ManagementApi::from_config(config, pooling, ActiveCounts::new())
        .expect("management API")
        .with_catalog(runtime);
    let mut management_headers = HeaderMap::new();
    management_headers.insert(
        http::header::HOST,
        http::HeaderValue::from_static("localhost"),
    );
    let models = api.handle(&Method::GET, "/models", &management_headers);
    assert_eq!(models.status, StatusCode::OK);
    let models: serde_json::Value = serde_json::from_slice(&models.body).expect("models JSON");
    assert_eq!(models["catalog_generation"], 1);
    assert!(models["models"]
        .as_array()
        .expect("model array")
        .iter()
        .any(|model| model["id"] == "configured-only"));
    let discovered = models["models"]
        .as_array()
        .expect("model array")
        .iter()
        .find(|model| model["id"] == "team/best")
        .expect("discovered alias");
    assert_eq!(discovered["selection_origin"], "discovered");
    assert_eq!(
        discovered["targets"][0]["provenance"][0]["revision"],
        "fixture-revision"
    );

    let catalog = api.handle(&Method::GET, "/catalog", &management_headers);
    assert_eq!(catalog.status, StatusCode::OK);
    let catalog_text = String::from_utf8(catalog.body).expect("catalog UTF-8");
    assert!(catalog_text.contains("\"prefix\":\"team\""));
    assert!(catalog_text.contains("\"alias\":\"best\""));
    assert!(catalog_text.contains("\"included_models\":[\"model-*\"]"));
    assert!(catalog_text.contains("\"excluded_models\":[\"*-old\"]"));
    assert!(!catalog_text.contains(SECRET_SENTINEL));
}

#[tokio::test]
async fn vendored_request_facts_reach_discovered_targets_and_the_model_view() {
    let config = pooler_config::compile_yaml(
        "catalog-model-facts.yaml",
        r#"
version: 1
management: {bind: 127.0.0.1:0}
upstreams:
  openai: {url: http://127.0.0.1:1}
  gateway: {url: http://127.0.0.1:2}
  private: {url: http://127.0.0.1:3}
catalog:
  sources:
    - {id: openai.primary, provider: openai, parser: open_ai, prefix: direct}
    - {id: gateway.primary, provider: gateway, parser: open_ai, prefix: gateway, model_facts_provider: openai}
    - {id: private.primary, provider: private, parser: open_ai, prefix: private}
"#,
    )
    .expect("model facts config");
    let body = br#"{"data":[{"id":"gpt-image-1.5"},{"id":"gpt-4o"}]}"#.as_slice();
    let registrations = ["openai.primary", "gateway.primary", "private.primary"]
        .into_iter()
        .map(|source| {
            let provider = Arc::new(FakeProvider::new([Ok(FetchedCatalog::new(body, None))]));
            CatalogFetcherRegistration::new(source, provider).expect("registration")
        })
        .collect();
    let runtime = CatalogRuntime::with_fetchers(
        config.catalog().expect("catalog plan").clone(),
        registrations,
    )
    .expect("runtime");
    runtime.refresh().await.expect("refresh");
    let snapshot = runtime.snapshot();

    let dialect = |public_id: &str| {
        snapshot
            .get(public_id)
            .unwrap_or_else(|| panic!("{public_id} is discovered"))
            .targets()[0]
            .dialect()
    };
    assert_eq!(
        dialect("direct/gpt-image-1.5").temperature,
        pooler_core::ParamSupport::Rejected,
        "a provider named like the upstream catalog resolves vendored facts"
    );
    assert_eq!(
        dialect("gateway/gpt-image-1.5").temperature,
        pooler_core::ParamSupport::Rejected,
        "model_facts_provider maps a locally named provider onto vendored facts"
    );
    assert!(
        dialect("private/gpt-image-1.5").is_default(),
        "a provider absent from the vendored snapshot keeps the protocol default"
    );
    assert!(
        dialect("direct/gpt-4o").is_default(),
        "models with no recorded deviation keep the protocol default"
    );

    let view = pooler_server::merged_model_catalog_value(&config, Some(&runtime));
    let rejected = view["models"]
        .as_array()
        .expect("model array")
        .iter()
        .find(|model| model["id"] == "direct/gpt-image-1.5")
        .expect("deviating model in the view");
    assert_eq!(
        rejected["targets"][0]["dialect"]["temperature"], "rejected",
        "the model view exposes the dialect that will shape upstream requests"
    );
}

#[tokio::test]
async fn operator_overrides_withhold_and_reshape_published_models() {
    let config = pooler_config::compile_yaml(
        "catalog-overrides.yaml",
        r#"
version: 1
management: {bind: 127.0.0.1:0}
upstreams:
  openai: {url: http://127.0.0.1:1}
catalog:
  sources:
    - {id: openai.primary, provider: openai, parser: open_ai}
  overrides:
    - {model: gpt-4o, disabled: true}
    - model: gpt-image-1.5
      display_name: Image Model
      capabilities: [text, reasoning]
      dialect: {temperature: accepted}
    - {model: never-served, disabled: true}
"#,
    )
    .expect("override config");
    let body =
        br#"{"data":[{"id":"gpt-image-1.5"},{"id":"gpt-4o"},{"id":"gpt-4o-mini"}]}"#.as_slice();
    let provider = Arc::new(FakeProvider::new([Ok(FetchedCatalog::new(body, None))]));
    let runtime = CatalogRuntime::with_fetchers(
        config.catalog().expect("catalog plan").clone(),
        vec![CatalogFetcherRegistration::new("openai.primary", provider).expect("registration")],
    )
    .expect("runtime");
    runtime.refresh().await.expect("refresh");
    let snapshot = runtime.snapshot();

    // A withheld model is absent from the published catalog, so no request can
    // resolve a target for it.
    assert!(
        snapshot.get("gpt-4o").is_none(),
        "a disabled model must not be published"
    );
    assert!(
        snapshot.get("gpt-4o-mini").is_some(),
        "disabling one model must not withhold its neighbours"
    );
    assert_eq!(
        snapshot
            .overrides()
            .disabled_models()
            .iter()
            .map(|model| model.as_str())
            .collect::<Vec<_>>(),
        ["gpt-4o"]
    );
    assert_eq!(
        snapshot
            .overrides()
            .unmatched_models()
            .iter()
            .map(|model| model.as_str())
            .collect::<Vec<_>>(),
        ["never-served"],
        "an override matching nothing is reported instead of failing the refresh"
    );

    // The operator's dialect outranks the vendored snapshot, which records this
    // model as rejecting temperature.
    let reshaped = snapshot.get("gpt-image-1.5").expect("reshaped model");
    assert_eq!(reshaped.display_name(), Some("Image Model"));
    assert!(
        reshaped.targets()[0].dialect().is_default(),
        "an operator dialect must outrank the vendored request facts"
    );
    assert!(reshaped.targets()[0]
        .capabilities()
        .contains(pooler_core::Capability::Reasoning));

    let view = pooler_server::merged_model_catalog_value(&config, Some(&runtime));
    let ids = view["models"]
        .as_array()
        .expect("model array")
        .iter()
        .map(|model| model["id"].as_str().expect("model id"))
        .collect::<Vec<_>>();
    assert!(
        !ids.contains(&"gpt-4o"),
        "the model view must not advertise a withheld model"
    );
    assert_eq!(view["model_overrides"]["disabled_models"][0], "gpt-4o");
    assert_eq!(
        view["model_overrides"]["unmatched_models"][0],
        "never-served"
    );
}

#[tokio::test]
async fn injected_fetcher_output_is_rechecked_against_the_source_body_bound() {
    let config = pooler_config::compile_yaml(
        "catalog-bound.yaml",
        r#"
version: 1
upstreams: {provider-a: {url: http://127.0.0.1:1}}
catalog:
  sources:
    - {id: provider-a.primary, provider: provider-a, parser: open_ai, max_response_bytes: 8}
"#,
    )
    .expect("bounded config");
    let provider = Arc::new(FakeProvider::new([Ok(FetchedCatalog::new(
        vec![b'x'; 9],
        None,
    ))]));
    let runtime = CatalogRuntime::with_fetchers(
        config.catalog().expect("catalog plan").clone(),
        vec![
            CatalogFetcherRegistration::new("provider-a.primary", provider).expect("registration"),
        ],
    )
    .expect("runtime");
    let error = runtime
        .refresh()
        .await
        .expect_err("oversized body rejected");
    assert!(matches!(
        error,
        pooler_model_catalog::CatalogError::DiscoveryFailed {
            kind: DiscoveryFailureKind::LimitExceeded,
            ..
        }
    ));
    assert_eq!(runtime.snapshot().generation(), 0);
}

#[tokio::test]
async fn startup_catalog_alias_selects_and_rewrites_a_real_proxy_request() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake provider bind");
    let upstream_address = upstream.local_addr().expect("fake provider address");
    let provider = tokio::spawn(async move {
        let (mut discovery, _) = upstream.accept().await.expect("discovery connection");
        let discovery_request = read_http_request(&mut discovery).await;
        assert!(discovery_request.starts_with("GET /v1/models HTTP/1.1"));
        let catalog = br#"{"data":[{"id":"provider-private"}]}"#;
        discovery
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\netag: runtime-r1\r\n\r\n",
                    catalog.len()
                )
                .as_bytes(),
            )
            .await
            .expect("catalog headers");
        discovery.write_all(catalog).await.expect("catalog body");

        let (mut inference, _) = upstream.accept().await.expect("inference connection");
        let inference_request = read_http_request(&mut inference).await;
        assert!(inference_request.starts_with("POST /v1/chat/completions HTTP/1.1"));
        assert!(
            inference_request.contains("\"model\":\"provider-private\""),
            "catalog alias must rewrite the upstream request: {inference_request}"
        );
        let response = br#"{"id":"response","model":"provider-private"}"#;
        inference
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response.len()
                )
                .as_bytes(),
            )
            .await
            .expect("inference headers");
        inference.write_all(response).await.expect("inference body");
    });

    let config = pooler_config::compile_yaml(
        "catalog-selection.yaml",
        &format!(
            r#"
version: 1
listeners: {{local: {{bind: 127.0.0.1:0}}}}
upstreams: {{provider-a: {{url: http://{upstream_address}}}}}
catalog:
  sources:
    - id: provider-a.primary
      provider: provider-a
      parser: kimi
      aliases: [{{name: provider-private, alias: public-alias, force_mapping: true}}]
routes:
  - id: chat
    listen: local
    match: {{method: POST, path: /v1/chat/completions}}
    ingress: {{mode: patch, inspectors: [inspect.openai.model]}}
    target: {{provider: provider-a, model_from: request.model}}
    response: {{mode: opaque}}
"#
        ),
    )
    .expect("alias selection config");
    let server = HttpProxyServer::bind(config)
        .await
        .expect("startup discovery succeeds");
    assert!(server
        .catalog()
        .expect("catalog runtime")
        .snapshot()
        .get("public-alias")
        .is_some());
    let proxy_address = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut downstream = TcpStream::connect(&proxy_address)
        .await
        .expect("proxy connection");
    let body = br#"{"model":"public-alias","messages":[{"role":"user","content":"hello"}]}"#;
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

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    provider.await.expect("fake provider task");
}

/// Serve one discovery response, then hand back any inference request that
/// arrives within a short window.
async fn serve_discovery_then_optional_inference(
    upstream: TcpListener,
    models: &'static [u8],
) -> Option<String> {
    let (mut discovery, _) = upstream.accept().await.expect("discovery connection");
    let request = read_http_request(&mut discovery).await;
    assert!(request.starts_with("GET /v1/models HTTP/1.1"));
    discovery
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                models.len()
            )
            .as_bytes(),
        )
        .await
        .expect("catalog headers");
    discovery.write_all(models).await.expect("catalog body");

    let accepted = tokio::time::timeout(std::time::Duration::from_millis(500), upstream.accept())
        .await
        .ok()?;
    let (mut inference, _) = accepted.expect("inference connection");
    let request = read_http_request(&mut inference).await;
    let response = br#"{"id":"response","model":"gpt-image-1.5"}"#;
    inference
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            )
            .as_bytes(),
        )
        .await
        .expect("inference headers");
    inference.write_all(response).await.expect("inference body");
    Some(request)
}

async fn proxy_a_request_rejecting_temperature(
    loss_policy: Option<&str>,
) -> (String, Option<String>) {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake provider bind");
    let upstream_address = upstream.local_addr().expect("fake provider address");
    let provider = tokio::spawn(serve_discovery_then_optional_inference(
        upstream,
        br#"{"data":[{"id":"gpt-image-1.5"}]}"#,
    ));

    let loss_policy =
        loss_policy.map_or_else(String::new, |policy| format!("    loss_policy: {policy}\n"));
    let config = pooler_config::compile_yaml(
        "catalog-dialect.yaml",
        &format!(
            r#"
version: 1
listeners: {{local: {{bind: 127.0.0.1:0}}}}
upstreams: {{openai: {{url: http://{upstream_address}}}}}
catalog:
  sources: [{{id: openai.primary, provider: openai, parser: open_ai}}]
routes:
  - id: chat
    listen: local
    match: {{method: POST, path: /v1/chat/completions}}
    ingress: {{mode: patch, inspectors: [inspect.openai.model]}}
    target: {{provider: openai, model_from: request.model}}
    response: {{mode: opaque}}
{loss_policy}"#
        ),
    )
    .expect("dialect route config");
    let server = HttpProxyServer::bind(config)
        .await
        .expect("startup discovery succeeds");
    let proxy_address = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut downstream = TcpStream::connect(&proxy_address)
        .await
        .expect("proxy connection");
    let body = br#"{"model":"gpt-image-1.5","temperature":0.7,"messages":[{"role":"user","content":"hi"}]}"#;
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

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let upstream_request = provider.await.expect("fake provider task");
    (
        String::from_utf8_lossy(&response).to_string(),
        upstream_request,
    )
}

#[tokio::test]
async fn a_rejected_parameter_is_dropped_before_the_upstream_request() {
    let (response, upstream_request) = proxy_a_request_rejecting_temperature(None).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let upstream_request = upstream_request.expect("upstream received the shaped request");
    assert!(
        !upstream_request.contains("temperature"),
        "the vendored dialect must drop a parameter the model rejects: {upstream_request}"
    );
    assert!(
        upstream_request.contains("\"model\":\"gpt-image-1.5\""),
        "{upstream_request}"
    );
    assert!(
        upstream_request.contains("\"messages\""),
        "{upstream_request}"
    );
}

#[tokio::test]
async fn a_rejecting_loss_policy_fails_the_request_before_any_upstream_call() {
    let (response, upstream_request) = proxy_a_request_rejecting_temperature(Some("reject")).await;

    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(
        upstream_request.is_none(),
        "no upstream request may be made: {upstream_request:?}"
    );
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.expect("request read");
        assert!(read > 0, "request closed before headers");
        bytes.extend_from_slice(&chunk[..read]);
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
            })
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut chunk).await.expect("request body read");
            assert!(read > 0, "request closed before body");
            bytes.extend_from_slice(&chunk[..read]);
        }
        return String::from_utf8(bytes).expect("request UTF-8");
    }
}
