use std::collections::BTreeMap;

use adapter_providers::{
    antigravity_compatibility_profile, kimi_coding_profile, kimi_open_platform_profile,
    try_into_catalog_response, vertex_profile, AdapterError, AntigravityAdapter,
    AntigravityCompatibilityConfig, AntigravityCreditParser, AuthPlacement, ContractStability,
    DangerousCustomEndpoint, KimiAdapter, ModelDiscoveryError, OpenAiCompatibleAdapter,
    ProviderAdapter, ProviderKind, ProviderModelParser, ProviderOperation, ProviderParseError,
    ProviderQuotaScope, ProviderResponseClassifier, ProviderSurface, VertexAdapter,
    VertexAuthentication, CLI_PROXY_API_REFERENCE_REVISION,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use pooler_auth::SecretValue;
use pooler_core::{Capability, ErrorClass};
use pooler_policy::{CredentialCausation, QuotaSignal, QuotaUnit};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

const FIXTURE: &str = include_str!("fixtures/provider-contracts.json");
const SECRET_SENTINEL: &str = "provider-secret-sentinel-7ef1";

#[derive(Debug, Deserialize)]
struct Fixture {
    openai_models: Value,
    vertex_models: Value,
    antigravity_hints: Value,
    antigravity_credits: Value,
    failures: Vec<FailureFixture>,
}

#[derive(Debug, Deserialize)]
struct FailureFixture {
    provider: ProviderKind,
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
    scope: Option<ProviderQuotaScope>,
    class: ErrorClass,
    retry_ms: Option<u64>,
    credential_proven: bool,
    has_cooldown: bool,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("provider fixture must decode")
}

fn header_map(values: &BTreeMap<String, String>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("fixture header name"),
            HeaderValue::from_str(value).expect("fixture header value"),
        );
    }
    headers
}

#[test]
fn profiles_keep_official_and_pinned_contracts_distinct() {
    let kimi = kimi_open_platform_profile();
    assert_eq!(kimi.surface, ProviderSurface::KimiOpenPlatform);
    assert_eq!(kimi.stability, ContractStability::OfficialPublic);
    assert!(kimi.operations.contains(&ProviderOperation::ListModels));

    let kimi_code = kimi_coding_profile();
    assert_eq!(kimi_code.surface, ProviderSurface::KimiCodingSubscription);
    assert_eq!(kimi_code.stability, ContractStability::PinnedCompatibility);
    assert_eq!(kimi_code.auth_endpoints.len(), 2);
    assert!(kimi_code
        .evidence
        .iter()
        .all(|item| { item.revision.as_deref() == Some(CLI_PROXY_API_REFERENCE_REVISION) }));

    let vertex = vertex_profile();
    assert_eq!(vertex.stability, ContractStability::OfficialPublic);
    assert!(!vertex.operations.contains(&ProviderOperation::ListModels));

    let antigravity = antigravity_compatibility_profile();
    assert_eq!(
        antigravity.stability,
        ContractStability::PinnedCompatibility
    );
    assert_eq!(antigravity.auth_endpoints.len(), 3);
    let serialized = serde_json::to_string(&antigravity).expect("serialize profile");
    assert!(!serialized.contains("client_secret"));
    assert!(!serialized.contains("client_id"));
    assert!(serialized.contains(CLI_PROXY_API_REFERENCE_REVISION));
}

#[test]
fn endpoint_builders_preserve_provider_specific_paths() {
    let kimi = KimiAdapter::open_platform().expect("Kimi adapter");
    assert_eq!(
        kimi.endpoint_candidates(ProviderOperation::ChatCompletions, None)
            .expect("Kimi chat endpoint")[0]
            .as_str(),
        "https://api.moonshot.ai/v1/chat/completions"
    );
    assert_eq!(
        kimi.endpoint_candidates(ProviderOperation::ListModels, None)
            .expect("Kimi model endpoint")[0]
            .as_str(),
        "https://api.moonshot.ai/v1/models"
    );

    let kimi_code = KimiAdapter::coding_subscription().expect("Kimi Code adapter");
    assert_eq!(
        kimi_code
            .endpoint_candidates(ProviderOperation::ChatCompletions, None)
            .expect("Kimi Code endpoint")[0]
            .as_str(),
        "https://api.kimi.com/coding/v1/chat/completions"
    );
    assert_eq!(
        kimi_code
            .normalize_model("kimi-k2.7-code[1m](high)")
            .expect("Kimi alias"),
        "kimi-for-coding(high)"
    );

    let vertex = VertexAdapter::project("fixture-project", "global").expect("Vertex adapter");
    assert_eq!(
        vertex
            .endpoint_candidates(
                ProviderOperation::StreamGenerateContent,
                Some("publishers/google/models/gemini-fixture"),
            )
            .expect("Vertex endpoint")[0]
            .as_str(),
        "https://aiplatform.googleapis.com/v1/projects/fixture-project/locations/global/publishers/google/models/gemini-fixture:streamGenerateContent?alt=sse"
    );

    let express = VertexAdapter::dangerously_express_api_key(
        Url::parse("https://vertex-compatible.example.com/api").expect("URL"),
        DangerousCustomEndpoint::acknowledge_risk(),
    )
    .expect("explicit custom Vertex adapter");
    assert_eq!(
        express
            .endpoint_candidates(ProviderOperation::CountTokens, Some("gemini-fixture"))
            .expect("Vertex express endpoint")[0]
            .as_str(),
        "https://vertex-compatible.example.com/api/v1/publishers/google/models/gemini-fixture:countTokens"
    );
}

#[test]
fn authorization_is_redacted_and_uses_the_correct_header() {
    let secret = SecretValue::new(SECRET_SENTINEL);
    let kimi = KimiAdapter::open_platform().expect("Kimi adapter");
    let auth = kimi.authorization(&secret).expect("Kimi auth");
    assert!(!format!("{auth:?}").contains(SECRET_SENTINEL));
    let mut headers = HeaderMap::new();
    auth.apply_to(&mut headers);
    assert_eq!(
        headers
            .get("authorization")
            .expect("authorization")
            .to_str()
            .expect("header text"),
        format!("Bearer {SECRET_SENTINEL}")
    );
    assert!(headers
        .get("authorization")
        .expect("authorization")
        .is_sensitive());

    let vertex = VertexAdapter::project_with_auth(
        "fixture-project",
        "us-central1",
        VertexAuthentication::ApiKey,
    )
    .expect("Vertex key adapter");
    let auth = vertex.authorization(&secret).expect("Vertex auth");
    assert_eq!(
        auth.header_name().map(HeaderName::as_str),
        Some("x-goog-api-key")
    );
    assert!(!format!("{auth:?}").contains(SECRET_SENTINEL));

    let invalid = SecretValue::new("line-one\nline-two");
    assert!(matches!(
        kimi.authorization(&invalid),
        Err(AdapterError::InvalidAuthorization)
    ));
}

#[test]
fn configured_auth_kinds_materialize_exact_provider_headers() {
    let secret = SecretValue::new(SECRET_SENTINEL);
    for (kind, expected_name, expected_value) in [
        (
            "bearer_secret",
            "authorization",
            format!("Bearer {SECRET_SENTINEL}"),
        ),
        ("x-api-key", "x-api-key", SECRET_SENTINEL.to_owned()),
        (
            "x-goog-api-key",
            "x-goog-api-key",
            SECRET_SENTINEL.to_owned(),
        ),
    ] {
        let placement = AuthPlacement::from_configured_kind(kind).expect("configured placement");
        let authorization = placement.materialize(&secret).expect("authorization");
        let mut headers = HeaderMap::new();
        authorization.apply_to(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers
                .get(expected_name)
                .expect("expected provider header")
                .to_str()
                .expect("header text"),
            expected_value
        );
    }
    assert!(matches!(
        AuthPlacement::from_configured_kind("basic"),
        Err(AdapterError::InvalidAuthorization)
    ));
}

#[test]
fn antigravity_is_disabled_until_explicitly_enabled_and_is_overrideable() {
    let disabled = AntigravityCompatibilityConfig::pinned_reference().expect("pinned config");
    assert_eq!(
        AntigravityAdapter::new(disabled.clone()),
        Err(AdapterError::CompatibilityNotEnabled)
    );

    let pinned = AntigravityAdapter::new(disabled.clone().enable()).expect("explicit opt-in");
    assert_eq!(
        pinned
            .endpoint_candidates(ProviderOperation::GenerateContent, None)
            .expect("pinned generate endpoints")[0]
            .as_str(),
        "https://daily-cloudcode-pa.googleapis.com/v1internal:generateContent"
    );
    assert_eq!(
        pinned
            .endpoint_candidates(ProviderOperation::StreamGenerateContent, None)
            .expect("pinned stream endpoints")[0]
            .as_str(),
        "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
    );
    assert_eq!(
        pinned
            .endpoint_candidates(ProviderOperation::FetchAvailableModels, None)
            .expect("pinned model-hint endpoints")[0]
            .as_str(),
        "https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels"
    );

    let mut untrusted = disabled.clone().enable();
    untrusted.inference_base_urls =
        vec![Url::parse("https://compat-one.example.com/root").expect("unrelated base")];
    assert_eq!(
        AntigravityAdapter::new(untrusted),
        Err(AdapterError::ProviderHostNotAllowed)
    );

    let mut configured = disabled
        .enable()
        .dangerously_allow_custom_endpoints(DangerousCustomEndpoint::acknowledge_risk());
    configured.inference_base_urls = vec![
        Url::parse("https://compat-one.example.com/root").expect("base one"),
        Url::parse("https://compat-two.example.com").expect("base two"),
    ];
    configured.paths.generate = "/compat:generate".to_owned();
    let adapter = AntigravityAdapter::new(configured).expect("opted-in adapter");
    let endpoints = adapter
        .endpoint_candidates(ProviderOperation::GenerateContent, None)
        .expect("compat endpoints");
    assert_eq!(
        endpoints[0].as_str(),
        "https://compat-one.example.com/root/compat:generate"
    );
    assert_eq!(
        endpoints[1].as_str(),
        "https://compat-two.example.com/compat:generate"
    );
    assert_eq!(
        adapter.profile().stability,
        ContractStability::PinnedCompatibility
    );
}

#[test]
fn generic_openai_compatibility_requires_an_explicit_operation_allow_list() {
    let adapter = OpenAiCompatibleAdapter::new(
        "fixture-provider",
        Url::parse("https://gateway.example.com/api/v1").expect("base URL"),
        AuthPlacement::custom("api-key", "").expect("custom auth"),
        [
            ProviderOperation::ListModels,
            ProviderOperation::ChatCompletions,
            ProviderOperation::Responses,
        ],
    )
    .expect("compat adapter");
    assert_eq!(adapter.provider_id().as_str(), "fixture-provider");
    assert_eq!(
        adapter
            .endpoint_candidates(ProviderOperation::Responses, None)
            .expect("responses endpoint")[0]
            .as_str(),
        "https://gateway.example.com/api/v1/responses"
    );
    assert_eq!(
        adapter.endpoint_candidates(ProviderOperation::ImageEdits, None),
        Err(AdapterError::UnsupportedOperation {
            operation: ProviderOperation::ImageEdits
        })
    );
}

#[test]
fn model_discovery_normalizes_explicit_provider_shapes() {
    let fixture = fixture();
    let parser = ProviderModelParser::default();
    let openai = parser
        .parse_kimi_list(&serde_json::to_vec(&fixture.openai_models).expect("JSON"))
        .expect("OpenAI list");
    assert_eq!(openai.len(), 2);
    assert_eq!(openai[0].id, "kimi-k2.6");
    assert!(openai[0].capabilities.contains(Capability::Text));
    assert!(openai[0].capabilities.contains(Capability::Images));
    assert!(openai[0].capabilities.contains(Capability::Reasoning));
    assert!(openai[0].capabilities.contains(Capability::FunctionCalling));
    assert_eq!(
        openai[0].attributes.get("supports_video_input"),
        Some(&"true".to_owned())
    );
    let generic = parser
        .parse_openai_list(&serde_json::to_vec(&fixture.openai_models).expect("JSON"))
        .expect("generic OpenAI list");
    assert!(!generic[1].capabilities.contains(Capability::Text));
    let catalog = try_into_catalog_response(openai.clone(), Some("fixture-revision".to_owned()))
        .expect("shared catalog DTO");
    assert_eq!(catalog.revision.as_deref(), Some("fixture-revision"));
    assert_eq!(catalog.models[0].id.as_str(), "kimi-k2.6");
    assert_eq!(catalog.models[0].capabilities, openai[0].capabilities);

    let vertex = parser
        .parse_vertex_catalog(&serde_json::to_vec(&fixture.vertex_models).expect("JSON"))
        .expect("Vertex catalog");
    assert_eq!(vertex[0].id, "gemini-fixture");
    assert_eq!(vertex[0].owned_by.as_deref(), Some("google"));
    assert!(vertex[0].capabilities.contains(Capability::Streaming));
    assert!(vertex[1].capabilities.contains(Capability::Images));

    let hints = parser
        .parse_antigravity_hints(&serde_json::to_vec(&fixture.antigravity_hints).expect("JSON"))
        .expect("Antigravity hints");
    assert!(hints.web_search_models.contains("gemini-fixture"));
    assert!(hints.web_search_models.contains("claude-fixture"));
}

#[test]
fn provider_specific_quota_fixtures_are_classified_without_false_causation() {
    for scenario in fixture().failures {
        let classifier = ProviderResponseClassifier::new(scenario.provider);
        let headers = header_map(&scenario.headers);
        let body = serde_json::to_vec(&scenario.body).expect("failure JSON");
        let quota = classifier
            .parse_quota(scenario.status, &headers, &body)
            .expect("bounded quota parse");
        assert_eq!(
            quota.as_ref().map(|quota| quota.scope()),
            scenario.scope,
            "scope for {:?}",
            scenario.provider
        );
        let classified = classifier.classify_response(scenario.status, &headers, &body);
        assert_eq!(
            classified.classification.class, scenario.class,
            "class for {:?}",
            scenario.provider
        );
        assert_eq!(
            classified
                .classification
                .recovery_after
                .map(|duration| u64::try_from(duration.as_millis()).expect("fixture duration")),
            scenario.retry_ms,
            "retry for {:?}",
            scenario.provider
        );
        assert_eq!(
            classified.credential_causation == CredentialCausation::Proven,
            scenario.credential_proven,
            "causation for {:?}",
            scenario.provider
        );
        assert_eq!(
            classified.cooldown.is_some(),
            scenario.has_cooldown,
            "cooldown for {:?}",
            scenario.provider
        );
    }
}

#[test]
fn antigravity_credit_fixture_is_bounded_and_actionable() {
    let fixture = fixture();
    let body = serde_json::to_vec(&fixture.antigravity_credits).expect("JSON");
    let credits = AntigravityCreditParser::default()
        .parse(&body)
        .expect("credit parse")
        .expect("credit entry");
    assert_eq!(credits.paid_tier_id(), Some("fixture-tier"));
    assert_eq!(credits.credit_type(), "GOOGLE_ONE_AI");
    assert_eq!(credits.credit_amount(), 12.5);
    assert_eq!(credits.minimum_credit_amount(), 1.25);
    assert!(credits.available());
    let policy = credits.to_policy_observation();
    assert_eq!(policy.unit, QuotaUnit::Credits);
    assert_eq!(policy.signal, QuotaSignal::Snapshot);
    assert_eq!(policy.remaining, Some(1));

    assert_eq!(
        AntigravityCreditParser::new(8, 1).parse(&body),
        Err(ProviderParseError::BodyTooLarge { limit: 8 })
    );
}

#[test]
fn oversized_and_malformed_bodies_are_bounded_and_redacted() {
    let secret_body = format!(
        "{{\"error\":{{\"code\":\"rate_limit_exceeded\",\"message\":\"{SECRET_SENTINEL}\"}}}}"
    );
    let classifier =
        ProviderResponseClassifier::with_max_body_bytes(ProviderKind::OpenAiCompatible, 16);
    let error = classifier
        .parse_quota(429, &HeaderMap::new(), secret_body.as_bytes())
        .expect_err("oversized body");
    assert_eq!(error, ProviderParseError::BodyTooLarge { limit: 16 });
    assert!(!format!("{error:?}").contains(SECRET_SENTINEL));
    let fallback = classifier.classify_response(429, &HeaderMap::new(), secret_body.as_bytes());
    assert_eq!(
        fallback.classification.class,
        ErrorClass::ProviderRateLimited
    );
    assert!(!format!("{fallback:?}").contains(SECRET_SENTINEL));

    let model_error = ProviderModelParser::new(8, 1, 8)
        .parse_openai_list(secret_body.as_bytes())
        .expect_err("bounded model body");
    assert_eq!(model_error, ModelDiscoveryError::BodyTooLarge { limit: 8 });
    assert!(!format!("{model_error:?}").contains(SECRET_SENTINEL));

    assert_eq!(
        ProviderResponseClassifier::new(ProviderKind::Vertex).parse_quota(
            429,
            &HeaderMap::new(),
            b"{not-json"
        ),
        Err(ProviderParseError::InvalidJson)
    );
}

#[test]
fn endpoint_identifiers_cannot_inject_paths_or_headers() {
    assert_eq!(
        VertexAdapter::project("project/escape", "global"),
        Err(AdapterError::InvalidIdentifier { field: "project" })
    );
    let vertex = VertexAdapter::project("fixture", "global").expect("Vertex adapter");
    assert_eq!(
        vertex.endpoint_candidates(
            ProviderOperation::GenerateContent,
            Some("gemini/../../escape"),
        ),
        Err(AdapterError::InvalidIdentifier { field: "model" })
    );
    assert_eq!(
        AuthPlacement::custom("bad\nheader", ""),
        Err(AdapterError::InvalidHeaderName)
    );
}

#[test]
fn built_in_endpoint_overrides_enforce_host_and_network_boundaries() {
    let kimi = KimiAdapter::open_platform().expect("Kimi adapter");
    assert_eq!(
        kimi.clone().with_base_url(
            Url::parse("https://unrelated.example.com/v1").expect("unrelated public URL")
        ),
        Err(AdapterError::ProviderHostNotAllowed)
    );
    let custom = kimi
        .clone()
        .dangerously_with_custom_base_url(
            Url::parse("https://unrelated.example.com/v1").expect("unrelated public URL"),
            DangerousCustomEndpoint::acknowledge_risk(),
        )
        .expect("explicit dangerous boundary");
    assert_eq!(
        custom
            .endpoint_candidates(ProviderOperation::ListModels, None)
            .expect("custom endpoint")[0]
            .as_str(),
        "https://unrelated.example.com/v1/v1/models"
    );

    for forbidden in [
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://[fe80::1]",
        "https://[::ffff:127.0.0.1]",
        "https://metadata.google.internal",
    ] {
        assert_eq!(
            kimi.clone().dangerously_with_custom_base_url(
                Url::parse(forbidden).expect("syntactically valid URL"),
                DangerousCustomEndpoint::acknowledge_risk(),
            ),
            Err(AdapterError::ForbiddenNetworkTarget),
            "forbidden target {forbidden}"
        );
    }

    assert_eq!(
        VertexAdapter::express_api_key(
            Url::parse("https://vertex-compatible.example.com").expect("custom Vertex URL")
        ),
        Err(AdapterError::ProviderHostNotAllowed)
    );
}

#[test]
fn antigravity_override_paths_are_validated_at_adapter_construction() {
    for invalid in [
        "relative",
        "//authority",
        "/v1//generate",
        "/v1/../generate",
        "/v1/%2e%2e/generate",
        "/v1?query=true",
        "/v1\\generate",
    ] {
        let mut config = AntigravityCompatibilityConfig::pinned_reference()
            .expect("pinned config")
            .enable();
        config.paths.generate = invalid.to_owned();
        assert_eq!(
            AntigravityAdapter::new(config),
            Err(AdapterError::InvalidOverridePath),
            "invalid path {invalid}"
        );
    }
}

#[test]
fn request_and_token_quota_windows_convert_without_collapsing_resets() {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("retry-after", "30"),
        ("x-ratelimit-limit-requests", "100"),
        ("x-ratelimit-remaining-requests", "0"),
        ("x-ratelimit-reset-requests", "2s"),
        ("x-ratelimit-limit-tokens", "10000"),
        ("x-ratelimit-remaining-tokens", "500"),
        ("x-ratelimit-reset-tokens", "1m30s"),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    let classifier = ProviderResponseClassifier::new(ProviderKind::OpenAiCompatible);
    let quota = classifier
        .parse_quota(429, &headers, br#"{"error":{"code":"insufficient_quota"}}"#)
        .expect("bounded parse")
        .expect("quota evidence");
    assert_eq!(quota.windows().len(), 2);
    assert_eq!(quota.windows()[0].unit(), QuotaUnit::Requests);
    assert_eq!(quota.windows()[0].remaining(), Some(0));
    assert_eq!(
        quota.windows()[0].reset_after(),
        Some(std::time::Duration::from_secs(2))
    );
    assert_eq!(quota.windows()[1].unit(), QuotaUnit::Tokens);
    assert_eq!(quota.windows()[1].limit(), Some(10_000));
    assert_eq!(
        quota.windows()[1].reset_after(),
        Some(std::time::Duration::from_secs(90))
    );
    assert_eq!(
        quota.strictest_recovery_after(),
        Some(std::time::Duration::from_secs(90))
    );
    let observations = quota.to_policy_observations();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].unit, QuotaUnit::Requests);
    assert_eq!(observations[1].unit, QuotaUnit::Tokens);
    assert_eq!(
        observations[1].reset_after,
        Some(std::time::Duration::from_secs(90))
    );
    assert_eq!(
        observations[1].retry_after,
        Some(std::time::Duration::from_secs(30))
    );
    assert_eq!(
        classifier
            .parse_policy_observations(
                429,
                &headers,
                br#"{"error":{"code":"insufficient_quota"}}"#,
            )
            .expect("direct policy DTO conversion"),
        observations
    );
}
