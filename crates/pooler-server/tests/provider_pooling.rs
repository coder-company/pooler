//! Binding-index selection coverage for cross-provider and same-origin pools.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use pooler_config::compile_yaml;
use pooler_http::PoolingCoordinator;
use pooler_policy::TelemetrySample;

fn pooled_config(
    strategy: &str,
    first_priority: u32,
    second_priority: u32,
) -> pooler_config::CompiledConfig {
    compile_yaml(
        "provider-pooling.yaml",
        &format!(
            r#"
version: 2
listeners:
  local: {{bind: 127.0.0.1:0}}
upstreams:
  first: {{url: http://127.0.0.1:1}}
  second: {{url: http://127.0.0.1:1}}
accounts:
  first-account: {{provider: first, secret: env:POOLER_FIRST}}
  second-account: {{provider: second, secret: env:POOLER_SECOND}}
account_pools:
  first-pool: {{provider: first, strategy: {strategy}, accounts: [first-account]}}
  second-pool: {{provider: second, strategy: {strategy}, accounts: [second-account]}}
models:
  - id: public-model
    targets:
      - {{id: first-target, provider: first, account_pool: first-pool, priority: {first_priority}, upstream_model: first-private, capabilities: [text], codecs: [], wire_family: openai}}
      - {{id: second-target, provider: second, account_pool: second-pool, priority: {second_priority}, upstream_model: second-private, capabilities: [text], codecs: [], wire_family: openai}}
policies:
  pooled:
    selection: {{strategy: {strategy}, affinity: {{key: header:x-session, ttl: 10m, rebind: true}}}}
    retry: {{maximum_attempts: 3, maximum_credentials: 3, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1s, maximum_total_delay: 2s}}
routes:
  - id: pooled
    listen: local
    target: {{provider: first, policy: pooled}}
"#
        ),
    )
    .expect("provider pooling config")
}

fn adaptive_config() -> pooler_config::CompiledConfig {
    compile_yaml(
        "adaptive-provider-pooling.yaml",
        r#"
version: 2
listeners:
  local: {bind: 127.0.0.1:0}
upstreams:
  first: {url: http://127.0.0.1:1}
  second: {url: http://127.0.0.1:1}
accounts:
  first-account: {provider: first, secret: env:POOLER_FIRST}
  second-account: {provider: second, secret: env:POOLER_SECOND}
account_pools:
  first-pool: {provider: first, accounts: [first-account]}
  second-pool: {provider: second, accounts: [second-account]}
models:
  - id: public-model
    targets:
      - {id: first-target, provider: first, account_pool: first-pool, priority: 1, upstream_model: first-private, capabilities: [text], codecs: [], wire_family: openai, price: 10}
      - {id: second-target, provider: second, account_pool: second-pool, priority: 1, upstream_model: second-private, capabilities: [text], codecs: [], wire_family: openai, price: 20}
policies:
  pooled:
    selection: {strategy: ordered_fallback}
    routing:
      order: [second, first]
      preference: {latency: true}
routes:
  - id: pooled
    listen: local
    target: {provider: first, policy: pooled}
"#,
    )
    .expect("adaptive provider pooling config")
}

#[test]
fn cross_provider_targets_use_explicit_priority_and_binding_identity() {
    let config = pooled_config("ordered_fallback", 1, 2);
    let coordinator = PoolingCoordinator::new(&config).expect("pooling coordinator");
    let route = config.route("pooled").expect("route");

    let selected = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &HeaderMap::new(),
            1,
            Instant::now(),
        )
        .expect("primary target is eligible");
    assert_eq!(selected.provider().as_str(), "first");
    assert_eq!(selected.upstream_model(), Some("first-private"));
    assert_eq!(selected.priority_tier(), Some(1));
    assert_eq!(
        selected.target_binding_id(),
        Some("public-model/first-target")
    );
    assert_eq!(
        selected.credential().map(pooler_core::CredentialId::as_str),
        Some("first-account")
    );
}

#[test]
fn disabling_primary_binding_allows_bounded_lower_tier_failover() {
    let config = pooled_config("ordered_fallback", 1, 2);
    let coordinator = PoolingCoordinator::new(&config).expect("pooling coordinator");
    coordinator
        .set_account_enabled("first-account", false)
        .expect("disable primary account");
    let route = config.route("pooled").expect("route");

    let selected = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &HeaderMap::new(),
            1,
            Instant::now(),
        )
        .expect("lower tier remains eligible");
    assert_eq!(selected.provider().as_str(), "second");
    assert_eq!(selected.priority_tier(), Some(2));
    assert_eq!(
        selected.target_binding_id(),
        Some("public-model/second-target")
    );
}

#[test]
fn same_priority_targets_are_poolable_without_provider_first_match() {
    let config = pooled_config("round_robin", 1, 1);
    let coordinator = PoolingCoordinator::new(&config).expect("pooling coordinator");
    let route = config.route("pooled").expect("route");
    let first = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &HeaderMap::new(),
            1,
            Instant::now(),
        )
        .expect("first same-tier target");
    let first_binding = first.target_binding_id().expect("binding").to_owned();
    drop(first);
    let second = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &HeaderMap::new(),
            2,
            Instant::now(),
        )
        .expect("second same-tier target");
    assert_ne!(second.target_binding_id(), Some(first_binding.as_str()));
    assert_eq!(second.priority_tier(), Some(1));
}

#[test]
fn model_publication_uses_any_eligible_binding() {
    let config = pooled_config("ordered_fallback", 1, 2);
    let coordinator = PoolingCoordinator::new(&config).expect("pooling coordinator");
    coordinator
        .set_account_enabled("first-account", false)
        .expect("disable primary account");
    let published = coordinator
        .published_models(&config, "first", pooler_core::CapabilitySet::new())
        .expect("published model view");
    assert_eq!(published.models(), &["public-model".to_owned()]);
}

#[test]
fn adaptive_latency_prefers_fresh_verified_telemetry() {
    let config = adaptive_config();
    let coordinator = PoolingCoordinator::new(&config).expect("pooling coordinator");
    let route = config.route("pooled").expect("route");
    let first = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &HeaderMap::new(),
            1,
            Instant::now(),
        )
        .expect("first target");
    assert_eq!(first.provider().as_str(), "second");
    let second_binding = first.binding_key().cloned().expect("second binding");
    drop(first);
    coordinator
        .set_account_enabled("second-account", false)
        .expect("temporarily disable second account");
    let second = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &HeaderMap::new(),
            2,
            Instant::now(),
        )
        .expect("second target");
    assert_eq!(second.provider().as_str(), "first");
    let first_binding = second.binding_key().cloned().expect("first binding");
    drop(second);
    coordinator
        .set_account_enabled("second-account", true)
        .expect("restore second account");
    let observed_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock")
        .as_millis() as u64;
    coordinator.record_routing_telemetry(
        first_binding,
        TelemetrySample {
            observed_at_ms,
            sample_count: 4,
            rolling_window_ms: 10_000,
            stale_after_ms: 10_000,
            latency_ms: Some(20),
            ..TelemetrySample::default()
        },
    );
    coordinator.record_routing_telemetry(
        second_binding,
        TelemetrySample {
            observed_at_ms,
            sample_count: 4,
            rolling_window_ms: 10_000,
            stale_after_ms: 10_000,
            latency_ms: Some(80),
            ..TelemetrySample::default()
        },
    );
    let selected = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &HeaderMap::new(),
            3,
            Instant::now(),
        )
        .expect("adaptive target");
    assert_eq!(selected.provider().as_str(), "first");
    assert_eq!(selected.model().as_str(), "public-model");
}

#[test]
fn request_body_cannot_override_dashboard_routing_policy() {
    let config = adaptive_config();
    let coordinator = PoolingCoordinator::new(&config).expect("pooling coordinator");
    let route = config.route("pooled").expect("route");
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-pooler-routing-metadata",
        http::HeaderValue::from_static("true"),
    );
    let selected = coordinator
        .select(
            &config,
            route,
            Some("public-model"),
            &headers,
            1,
            Instant::now(),
        )
        .expect("configured policy selection");
    assert_eq!(selected.provider().as_str(), "second");
}
