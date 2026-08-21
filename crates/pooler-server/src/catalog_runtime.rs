//! Bounded provider discovery wired to the shared model catalog.
//!
//! Configuration names existing upstreams and accounts. This module reuses
//! their authentication boundary, parses provider responses through
//! `adapter-providers`, and publishes only a complete merged snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use adapter_providers::{
    try_into_catalog_response, DiscoveredModel as ProviderModel, ModelDiscoveryError,
    ProviderModelParser,
};
use bytes::Bytes;
use http::{header, HeaderMap, Method, Request, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use pooler_auth::CredentialId;
use pooler_config::{
    AccountPlan, CatalogParserKind, CompiledConfig, ModelCatalogPlan, ModelCatalogSourcePlan,
    UpstreamPlan,
};
use pooler_core::{Capability, CapabilitySet};
use pooler_http::{
    apply_configured_account_auth, apply_configured_upstream_auth,
    apply_configured_upstream_headers, collect_body_limited, NativeAuthorizationRequest,
    NativeRuntime,
};
use pooler_model_catalog::{
    CatalogError, CatalogService, CatalogSnapshot, DiscoveryFailure, DiscoveryFailureKind,
    DiscoveryFuture, DiscoveryResponse, ModelDiscovery, ModelFacts, ProviderCatalog, RefreshReport,
    RegisteredSource, SourceId,
};
use serde_json::{json, Value};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const MAX_PROVIDER_STRING_BYTES: usize = pooler_model_catalog::MAX_DISPLAY_NAME_BYTES;

type CatalogHttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Raw provider response accepted from an injected discovery transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchedCatalog {
    body: Bytes,
    revision: Option<String>,
}

impl FetchedCatalog {
    /// Construct a response. The registered source bound is enforced before parsing.
    #[must_use]
    pub fn new(body: impl Into<Bytes>, revision: Option<String>) -> Self {
        Self {
            body: body.into(),
            revision,
        }
    }

    fn body(&self) -> &[u8] {
        &self.body
    }

    fn revision(&self) -> Option<String> {
        self.revision.clone()
    }
}

/// Boxed future returned by a provider model-list transport.
pub type CatalogFetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<FetchedCatalog, DiscoveryFailure>> + Send + 'a>>;

/// Narrow, injectable transport for one provider discovery source.
pub trait ProviderCatalogFetcher: Send + Sync {
    /// Fetch at most `max_response_bytes`; the runtime verifies the result too.
    fn fetch(&self, max_response_bytes: usize) -> CatalogFetchFuture<'_>;
}

/// One source ID paired with an injected transport.
#[derive(Clone)]
pub struct CatalogFetcherRegistration {
    source_id: SourceId,
    fetcher: Arc<dyn ProviderCatalogFetcher>,
}

impl CatalogFetcherRegistration {
    /// Register a transport for one compiled source ID.
    pub fn new(
        source_id: impl Into<String>,
        fetcher: Arc<dyn ProviderCatalogFetcher>,
    ) -> Result<Self, CatalogRuntimeError> {
        let source_id =
            SourceId::new(source_id).map_err(|_| CatalogRuntimeError::InvalidSourceIdentifier)?;
        Ok(Self { source_id, fetcher })
    }
}

impl std::fmt::Debug for CatalogFetcherRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CatalogFetcherRegistration")
            .field("source_id", &self.source_id)
            .field("fetcher", &"<provider-catalog-fetcher>")
            .finish()
    }
}

/// Runtime bridge from configured provider transports to an atomic catalog.
pub struct CatalogRuntime {
    plan: ModelCatalogPlan,
    service: Arc<CatalogService>,
    last_observed_at_unix_ms: AtomicU64,
}

impl CatalogRuntime {
    /// Build production fetchers from existing upstream/account plans.
    pub fn from_config(
        config: &CompiledConfig,
        native: Arc<NativeRuntime>,
    ) -> Result<Option<Arc<Self>>, CatalogRuntimeError> {
        let Some(plan) = config.catalog().cloned() else {
            return Ok(None);
        };
        let clients = CatalogHttpClients::new()?;
        let mut registrations = Vec::with_capacity(plan.sources().len());
        for source in plan.sources() {
            let upstream = config
                .upstreams()
                .get(source.source().provider().as_str())
                .cloned()
                .ok_or(CatalogRuntimeError::MissingProvider)?;
            let account = source
                .account()
                .map(|account| {
                    config
                        .accounts()
                        .get(account)
                        .cloned()
                        .ok_or(CatalogRuntimeError::MissingAccount)
                })
                .transpose()?;
            let fetcher = Arc::new(HttpProviderCatalogFetcher::new(
                clients.clone(),
                upstream,
                account,
                source,
                Arc::clone(&native),
            )?);
            registrations.push(CatalogFetcherRegistration {
                source_id: source.source().id().clone(),
                fetcher,
            });
        }
        Self::with_fetchers(plan, registrations).map(|runtime| Some(Arc::new(runtime)))
    }

    /// Build from injected transports, used by provider plugins and tests.
    pub fn with_fetchers(
        plan: ModelCatalogPlan,
        registrations: Vec<CatalogFetcherRegistration>,
    ) -> Result<Self, CatalogRuntimeError> {
        let mut fetchers = BTreeMap::new();
        for registration in registrations {
            if fetchers
                .insert(registration.source_id.clone(), registration.fetcher)
                .is_some()
            {
                return Err(CatalogRuntimeError::DuplicateFetcher {
                    source_id: registration.source_id,
                });
            }
        }

        let configured = plan
            .sources()
            .iter()
            .map(|source| source.source().id().clone())
            .collect::<BTreeSet<_>>();
        if let Some(source_id) = fetchers.keys().find(|id| !configured.contains(*id)) {
            return Err(CatalogRuntimeError::UnknownFetcher {
                source_id: source_id.clone(),
            });
        }

        let mut sources = Vec::with_capacity(plan.sources().len());
        for source in plan.sources() {
            let fetcher = fetchers.remove(source.source().id()).ok_or_else(|| {
                CatalogRuntimeError::MissingFetcher {
                    source_id: source.source().id().clone(),
                }
            })?;
            let discovery = Arc::new(ParsedProviderDiscovery::new(
                source,
                plan.limits().max_models_per_source(),
                fetcher,
            ));
            sources.push(RegisteredSource::new(source.source().clone(), discovery));
        }
        let service =
            CatalogService::new(sources, plan.limits())?.with_overrides(plan.overrides().clone());
        Ok(Self {
            plan,
            service: Arc::new(service),
            last_observed_at_unix_ms: AtomicU64::new(0),
        })
    }

    /// Refresh and publish using a process-monotonic wall-clock observation.
    pub async fn refresh(&self) -> Result<RefreshReport, CatalogError> {
        self.service.refresh(self.next_observation_time()).await
    }

    /// Current immutable merged snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<CatalogSnapshot> {
        self.service.snapshot()
    }

    /// Shared service handle consumed by request selection.
    #[must_use]
    pub fn service(&self) -> Arc<CatalogService> {
        Arc::clone(&self.service)
    }

    /// Compiled source policy and parser metadata for management diagnostics.
    #[must_use]
    pub const fn plan(&self) -> &ModelCatalogPlan {
        &self.plan
    }

    fn next_observation_time(&self) -> u64 {
        let wall_clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            });
        let mut previous = self.last_observed_at_unix_ms.load(Ordering::Acquire);
        loop {
            let next = wall_clock.max(previous.saturating_add(1));
            match self.last_observed_at_unix_ms.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(current) => previous = current,
            }
        }
    }
}

impl std::fmt::Debug for CatalogRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CatalogRuntime")
            .field("source_count", &self.plan.sources().len())
            .field("generation", &self.snapshot().generation())
            .finish_non_exhaustive()
    }
}

/// Catalog construction failure. Variants never retain provider response text.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CatalogRuntimeError {
    #[error("invalid catalog source identifier")]
    InvalidSourceIdentifier,
    #[error("catalog source references a missing provider")]
    MissingProvider,
    #[error("catalog source references a missing account")]
    MissingAccount,
    #[error("catalog source has an invalid endpoint")]
    InvalidEndpoint,
    #[error("catalog TLS client could not be initialized")]
    TlsClient,
    #[error("catalog source {source_id} has no registered fetcher")]
    MissingFetcher { source_id: SourceId },
    #[error("catalog source {source_id} has more than one registered fetcher")]
    DuplicateFetcher { source_id: SourceId },
    #[error("catalog fetcher {source_id} is not configured")]
    UnknownFetcher { source_id: SourceId },
    #[error(transparent)]
    Catalog(#[from] CatalogError),
}

struct ParsedProviderDiscovery {
    parser_kind: CatalogParserKind,
    parser: ProviderModelParser,
    max_response_bytes: usize,
    model_facts_provider: String,
    fetcher: Arc<dyn ProviderCatalogFetcher>,
}

impl ParsedProviderDiscovery {
    fn new(
        source: &ModelCatalogSourcePlan,
        max_models: usize,
        fetcher: Arc<dyn ProviderCatalogFetcher>,
    ) -> Self {
        let max_response_bytes = usize::try_from(source.max_response_bytes())
            .expect("catalog response hard bound fits usize");
        Self {
            parser_kind: source.parser(),
            parser: ProviderModelParser::new(
                max_response_bytes,
                max_models,
                MAX_PROVIDER_STRING_BYTES,
            ),
            max_response_bytes,
            model_facts_provider: source.model_facts_provider().to_owned(),
            fetcher,
        }
    }

    fn parse(&self, fetched: FetchedCatalog) -> Result<DiscoveryResponse, DiscoveryFailure> {
        if fetched.body().len() > self.max_response_bytes {
            return Err(DiscoveryFailure::from_kind(
                DiscoveryFailureKind::LimitExceeded,
            ));
        }
        let models = match self.parser_kind {
            CatalogParserKind::OpenAi => self.parser.parse_openai_list(fetched.body()),
            CatalogParserKind::Kimi => self.parser.parse_kimi_list(fetched.body()),
            CatalogParserKind::Gemini => self.parser.parse_gemini_list(fetched.body()),
            CatalogParserKind::Vertex => self.parser.parse_vertex_catalog(fetched.body()),
            CatalogParserKind::Antigravity => self
                .parser
                .parse_antigravity_hints(fetched.body())
                .map(|hints| {
                    hints
                        .web_search_models
                        .into_iter()
                        .map(|id| ProviderModel {
                            id,
                            display_name: None,
                            owned_by: None,
                            created: None,
                            context_length: None,
                            capabilities: CapabilitySet::new(),
                            attributes: BTreeMap::new(),
                        })
                        .collect()
                }),
        }
        .map_err(discovery_parse_failure)?;
        let mut response = try_into_catalog_response(models, fetched.revision())
            .map_err(discovery_parse_failure)?;
        self.apply_model_facts(&mut response);
        Ok(response)
    }

    /// Attach vendored request-shaping facts the provider response cannot carry.
    ///
    /// Provider model lists report availability, not request shape. Facts are
    /// keyed by the upstream model ID so a source that renames or prefixes a
    /// model for clients still resolves the upstream model's real dialect.
    fn apply_model_facts(&self, response: &mut DiscoveryResponse) {
        let provider = ProviderCatalog::builtin().get(&self.model_facts_provider);
        let facts = ModelFacts::builtin();
        for model in &mut response.models {
            if let Some(provider) = provider {
                for name in &provider.integration.capabilities {
                    if let Some(capability) = Capability::ALL
                        .into_iter()
                        .find(|capability| capability.as_str() == name)
                    {
                        model.capabilities.insert(capability);
                    }
                }
            }
            let mut profile = facts.profile(&self.model_facts_provider, model.id.as_str());
            if let Some(provider) = provider {
                if profile.streaming.is_unknown()
                    && provider
                        .integration
                        .capabilities
                        .iter()
                        .any(|capability| capability == "streaming")
                {
                    profile.streaming = pooler_core::FactSupport::Supported;
                }
                profile.token_limit_field = match provider.integration.request_dialect.as_str() {
                    "anthropic" => pooler_core::TokenLimitField::MaxTokens,
                    "gemini" => pooler_core::TokenLimitField::GenerationConfigMaxOutputTokens,
                    _ => profile.token_limit_field,
                };
                profile.request_transform = match provider.integration.native_kind.as_str() {
                    "xai" => pooler_core::ModelRequestTransform::XaiChat,
                    "kimi" => pooler_core::ModelRequestTransform::KimiChat,
                    _ => match provider.integration.request_dialect.as_str() {
                        "openai" => pooler_core::ModelRequestTransform::OpenAiChat,
                        "anthropic" => pooler_core::ModelRequestTransform::AnthropicMessages,
                        "gemini" => pooler_core::ModelRequestTransform::GeminiGenerateContent,
                        _ => profile.request_transform,
                    },
                };
                for family in &provider.integration.endpoint_families {
                    match family.as_str() {
                        "chat_completions" => profile.endpoint_variants.chat_completions = true,
                        "responses" => profile.endpoint_variants.responses = true,
                        "messages" => profile.endpoint_variants.messages = true,
                        "generate_content" | "stream_generate_content" => {
                            profile.endpoint_variants.generate_content = true;
                        }
                        "realtime" => profile.endpoint_variants.realtime = true,
                        _ => {}
                    }
                }
            }
            apply_profile_capabilities(&mut model.capabilities, profile);
            model.dialect = profile.dialect;
            model.profile = profile;
        }
    }
}

fn apply_profile_capabilities(
    capabilities: &mut CapabilitySet,
    profile: pooler_core::ModelProfile,
) {
    update_capability(capabilities, Capability::Reasoning, profile.reasoning);
    update_capability(capabilities, Capability::Tools, profile.tools);
    update_capability(capabilities, Capability::FunctionCalling, profile.tools);
    update_capability(
        capabilities,
        Capability::StructuredOutput,
        profile.structured_output,
    );
    update_capability(
        capabilities,
        Capability::JsonSchema,
        profile.structured_output,
    );
    update_capability(capabilities, Capability::Streaming, profile.streaming);
    if profile.attachments.is_supported()
        || profile.input_modalities.pdf
        || profile.input_modalities.video
    {
        capabilities.insert(Capability::Files);
    } else if profile.attachments.is_unsupported() {
        capabilities.remove(Capability::Files);
    }
    if profile.input_modalities.text || profile.output_modalities.text {
        capabilities.insert(Capability::Text);
    }
    if profile.input_modalities.image || profile.output_modalities.image {
        capabilities.insert(Capability::Images);
    }
    if profile.input_modalities.audio || profile.output_modalities.audio {
        capabilities.insert(Capability::Audio);
    }
    if profile.input_modalities.audio {
        capabilities.insert(Capability::InputAudio);
    }
    if profile.output_modalities.audio {
        capabilities.insert(Capability::OutputAudio);
    }
    if (!profile.input_modalities.is_empty() || !profile.output_modalities.is_empty())
        && !profile.input_modalities.image
        && !profile.output_modalities.image
    {
        capabilities.remove(Capability::Images);
    }
    if !profile.input_modalities.is_empty() && !profile.input_modalities.audio {
        capabilities.remove(Capability::InputAudio);
    }
    if !profile.output_modalities.is_empty() && !profile.output_modalities.audio {
        capabilities.remove(Capability::OutputAudio);
    }
}

fn update_capability(
    capabilities: &mut CapabilitySet,
    capability: Capability,
    support: pooler_core::FactSupport,
) {
    if support.is_supported() {
        capabilities.insert(capability);
    } else if support.is_unsupported() {
        capabilities.remove(capability);
    }
}

impl ModelDiscovery for ParsedProviderDiscovery {
    fn discover(&self) -> DiscoveryFuture<'_> {
        Box::pin(async move {
            let fetched = self.fetcher.fetch(self.max_response_bytes).await?;
            self.parse(fetched)
        })
    }
}

fn discovery_parse_failure(error: ModelDiscoveryError) -> DiscoveryFailure {
    let kind = match error {
        ModelDiscoveryError::BodyTooLarge { .. } | ModelDiscoveryError::TooManyModels { .. } => {
            DiscoveryFailureKind::LimitExceeded
        }
        ModelDiscoveryError::InvalidJson
        | ModelDiscoveryError::InvalidShape
        | ModelDiscoveryError::InvalidModel { .. }
        | ModelDiscoveryError::InvalidCatalogIdentifier => DiscoveryFailureKind::InvalidResponse,
    };
    DiscoveryFailure::from_kind(kind)
}

#[derive(Clone)]
struct CatalogHttpClients {
    standard: CatalogHttpClient,
    h2c: CatalogHttpClient,
}

impl CatalogHttpClients {
    fn new() -> Result<Self, CatalogRuntimeError> {
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| CatalogRuntimeError::TlsClient)?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let mut standard_builder = Client::builder(TokioExecutor::new());
        standard_builder.http2_adaptive_window(true);
        let standard = standard_builder.build(connector);

        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| CatalogRuntimeError::TlsClient)?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let mut h2c_builder = Client::builder(TokioExecutor::new());
        h2c_builder.http2_only(true).http2_adaptive_window(true);
        let h2c = h2c_builder.build(connector);
        Ok(Self { standard, h2c })
    }
}

struct HttpProviderCatalogFetcher {
    clients: CatalogHttpClients,
    upstream: UpstreamPlan,
    account: Option<AccountPlan>,
    endpoint: http::Uri,
    method: Method,
    native: Arc<NativeRuntime>,
}

impl HttpProviderCatalogFetcher {
    fn new(
        clients: CatalogHttpClients,
        upstream: UpstreamPlan,
        account: Option<AccountPlan>,
        source: &ModelCatalogSourcePlan,
        native: Arc<NativeRuntime>,
    ) -> Result<Self, CatalogRuntimeError> {
        if !matches!(upstream.url().scheme(), "http" | "https") {
            return Err(CatalogRuntimeError::InvalidEndpoint);
        }
        let endpoint = upstream
            .url()
            .join(source.path())
            .ok()
            .and_then(|url| url.as_str().parse().ok())
            .ok_or(CatalogRuntimeError::InvalidEndpoint)?;
        let method = if source.parser() == CatalogParserKind::Antigravity {
            Method::POST
        } else {
            Method::GET
        };
        Ok(Self {
            clients,
            upstream,
            account,
            endpoint,
            method,
            native,
        })
    }

    async fn send(&self, max_response_bytes: usize) -> Result<FetchedCatalog, DiscoveryFailure> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        );
        apply_configured_upstream_headers(&mut headers, &self.upstream)
            .map_err(|_| authentication_failure())?;
        let cancellation = CancellationToken::new();
        let credential = self
            .account
            .as_ref()
            .map(|account| CredentialId::new(account.id()))
            .transpose()
            .map_err(|_| authentication_failure())?;
        let native_authorization = self
            .native
            .authorize_selected_attempt(NativeAuthorizationRequest::new(
                &self.upstream,
                self.account.as_ref().map(AccountPlan::auth_kind),
                credential.as_ref(),
                self.account.as_ref().and_then(AccountPlan::secret),
                self.upstream.auth(),
                &headers,
                cancellation,
            ))
            .await
            .map_err(|_| authentication_failure())?;
        if let Some(authorization) = native_authorization {
            authorization
                .apply_to(&mut headers)
                .map_err(|_| authentication_failure())?;
        } else if let Some(account) = &self.account {
            let configured_kind = self.upstream.auth().map(|auth| auth.kind());
            apply_configured_account_auth(&mut headers, account.secret(), configured_kind)
                .map_err(|_| authentication_failure())?;
        } else if self.upstream.oauth().is_some() {
            return Err(authentication_failure());
        } else {
            apply_configured_upstream_auth(&mut headers, &self.upstream)
                .map_err(|_| authentication_failure())?;
        }

        let body = if self.method == Method::POST {
            headers.insert(
                header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            Bytes::from_static(b"{}")
        } else {
            Bytes::new()
        };
        let mut request = Request::new(Full::new(body));
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = self.endpoint.clone();
        *request.headers_mut() = headers;
        let client = if self.upstream.http2() && self.upstream.url().scheme() == "http" {
            &self.clients.h2c
        } else {
            &self.clients.standard
        };
        let response = client
            .request(request)
            .await
            .map_err(|_| DiscoveryFailure::from_kind(DiscoveryFailureKind::Transport))?;
        read_provider_response(response, max_response_bytes).await
    }
}

impl ProviderCatalogFetcher for HttpProviderCatalogFetcher {
    fn fetch(&self, max_response_bytes: usize) -> CatalogFetchFuture<'_> {
        Box::pin(self.send(max_response_bytes))
    }
}

async fn read_provider_response(
    response: http::Response<Incoming>,
    max_response_bytes: usize,
) -> Result<FetchedCatalog, DiscoveryFailure> {
    let status = response.status();
    let revision = response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= pooler_model_catalog::MAX_REVISION_BYTES)
        .map(str::to_owned);
    if !status.is_success() {
        return Err(DiscoveryFailure::from_kind(
            if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                DiscoveryFailureKind::Authentication
            } else {
                DiscoveryFailureKind::Provider
            },
        ));
    }
    let body = collect_body_limited(response.into_body(), max_response_bytes)
        .await
        .map_err(|error| match error {
            pooler_http::BodyLimitError::TooLarge { .. } => {
                DiscoveryFailure::from_kind(DiscoveryFailureKind::LimitExceeded)
            }
            _ => DiscoveryFailure::from_kind(DiscoveryFailureKind::Transport),
        })?;
    Ok(FetchedCatalog::new(body, revision))
}

fn authentication_failure() -> DiscoveryFailure {
    DiscoveryFailure::from_kind(DiscoveryFailureKind::Authentication)
}

/// Build the deterministic read-only model view shared by CLI and management.
#[must_use]
pub fn merged_model_catalog_value(
    config: &CompiledConfig,
    catalog: Option<&CatalogRuntime>,
) -> Value {
    let snapshot = catalog.map(CatalogRuntime::snapshot);
    let mut models = config
        .models()
        .values()
        .map(|model| {
            let targets = model
                .targets()
                .iter()
                .map(|target| {
                    json!({
                        "provider": target.provider(),
                        "upstream_model": target.upstream_model(),
                        "capabilities": target
                            .capabilities()
                            .iter()
                            .map(|capability| capability.as_str())
                            .collect::<Vec<_>>(),
                        "codecs": target.codecs().iter().map(AsRef::as_ref).collect::<Vec<&str>>(),
                    })
                })
                .collect::<Vec<_>>();
            (
                model.id().to_owned(),
                json!({
                    "id": model.id(),
                    "selection_origin": "configured",
                    "targets": targets,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();

    if let Some(snapshot) = snapshot.as_deref() {
        for model in snapshot.models().values() {
            let discovered = discovered_model_value(model);
            if let Some(configured) = models.get_mut(model.id().as_str()) {
                configured
                    .as_object_mut()
                    .expect("configured model view is an object")
                    .insert("discovery".to_owned(), discovered);
            } else {
                models.insert(model.id().to_string(), discovered);
            }
        }
    }

    let catalog_sources = catalog.map_or_else(Vec::new, |catalog| {
        let snapshot = snapshot
            .as_deref()
            .expect("catalog runtime always has a snapshot");
        catalog
            .plan()
            .sources()
            .iter()
            .map(|source| catalog_source_value(source, snapshot))
            .collect()
    });
    json!({
        "configuration_generation": config.generation(),
        "catalog_generation": snapshot.as_deref().map_or(0, CatalogSnapshot::generation),
        "catalog_refreshed_at_unix_ms": snapshot
            .as_deref()
            .map_or(0, CatalogSnapshot::refreshed_at_unix_ms),
        "models": models.into_values().collect::<Vec<_>>(),
        "catalog_sources": catalog_sources,
        "model_overrides": snapshot.as_deref().map_or_else(
            || json!({"disabled_models": [], "unmatched_models": []}),
            |snapshot| json!(snapshot.overrides()),
        ),
    })
}

/// List the public model IDs from the same merged snapshot used by selection.
#[must_use]
pub fn merged_model_ids(config: &CompiledConfig, catalog: Option<&CatalogRuntime>) -> Vec<String> {
    let mut ids = config
        .models()
        .keys()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if let Some(catalog) = catalog {
        ids.extend(catalog.snapshot().models().keys().map(ToString::to_string));
    }
    ids.into_iter().collect()
}

fn discovered_model_value(model: &pooler_model_catalog::CatalogModel) -> Value {
    let targets = model
        .targets()
        .iter()
        .map(|target| {
            json!({
                "provider": target.provider(),
                "upstream_model": target.upstream_model(),
                "capabilities": target
                    .capabilities()
                    .iter()
                    .map(|capability| capability.as_str())
                    .collect::<Vec<_>>(),
                "dialect": target.dialect(),
                "profile": target.profile(),
                "force_mapping": target.force_mapping(),
                "priority": target.priority(),
                "provenance": target.provenance(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "id": model.id(),
        "display_name": model.display_name(),
        "selection_origin": "discovered",
        "targets": targets,
        "request_overlay": model.request_overlay(),
    })
}

fn catalog_source_value(plan: &ModelCatalogSourcePlan, snapshot: &CatalogSnapshot) -> Value {
    let source = plan.source();
    let aliases = source
        .aliases()
        .iter()
        .map(|alias| {
            json!({
                "name": alias.upstream_id(),
                "alias": alias.public_id(),
                "fork": alias.fork(),
                "display_name": alias.display_name(),
                "force_mapping": alias.force_mapping(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "id": source.id(),
        "provider": source.provider(),
        "parser": plan.parser(),
        "path": plan.path(),
        "max_response_bytes": plan.max_response_bytes(),
        "account": plan.account(),
        "account_configured": plan.account().is_some(),
        "prefix": source.prefix(),
        "priority": source.priority(),
        "aliases": aliases,
        "included_models": source.included_models().collect::<Vec<_>>(),
        "excluded_models": source.excluded_models().collect::<Vec<_>>(),
        "state": snapshot.sources().get(source.id()),
    })
}
