//! Deterministic model discovery, catalog merging, and atomic refresh.
//!
//! Provider adapters implement [`ModelDiscovery`] and return bounded model
//! metadata. This crate applies source-local exclusions, aliases, and prefixes,
//! then publishes one immutable [`CatalogSnapshot`]. A failed refresh never
//! replaces the last good snapshot.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use futures_util::{stream, StreamExt};
use pooler_core::{CapabilitySet, ComponentId, IdentifierError, ModelId, ProviderId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio::sync::Semaphore;

/// Maximum aliases accepted for one discovery source.
pub const MAX_ALIASES_PER_SOURCE: usize = 1_024;
/// Maximum inclusion patterns accepted for one discovery source.
pub const MAX_INCLUSIONS_PER_SOURCE: usize = 1_024;
/// Maximum exclusion patterns accepted for one discovery source.
pub const MAX_EXCLUSIONS_PER_SOURCE: usize = 1_024;
/// Maximum UTF-8 bytes accepted for a model display name.
pub const MAX_DISPLAY_NAME_BYTES: usize = 512;
/// Maximum UTF-8 bytes accepted for a provider catalog revision.
pub const MAX_REVISION_BYTES: usize = 512;
/// Hard upper bound for configured discovery sources.
pub const HARD_MAX_SOURCES: usize = 1_024;
/// Hard upper bound for models returned by one discovery source.
pub const HARD_MAX_MODELS_PER_SOURCE: usize = 50_000;
/// Hard upper bound for models considered by one refresh.
pub const HARD_MAX_TOTAL_MODELS: usize = 100_000;
/// Hard upper bound for simultaneous provider discovery calls.
pub const HARD_MAX_REFRESH_CONCURRENCY: usize = 64;
/// Hard upper bound for a complete refresh.
pub const HARD_MAX_REFRESH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Hard upper bound for model/rule comparisons during one merge.
pub const HARD_MAX_MERGE_OPERATIONS: usize = 20_000_000;

const DEFAULT_MAX_SOURCES: usize = 64;
const DEFAULT_MAX_MODELS_PER_SOURCE: usize = 5_000;
const DEFAULT_MAX_TOTAL_MODELS: usize = 20_000;
const DEFAULT_MAX_REFRESH_CONCURRENCY: usize = 8;
const DEFAULT_MAX_MERGE_OPERATIONS: usize = 5_000_000;
const DEFAULT_REFRESH_TIMEOUT_MS: u64 = 30_000;

/// Stable, non-secret identifier for one model discovery source.
///
/// A source normally identifies a provider/account class, not an email address,
/// token, or other credential material.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct SourceId(ComponentId);

impl SourceId {
    /// Construct a source identifier after validating its component syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        ComponentId::new(value).map(Self)
    }

    /// Return the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for SourceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for SourceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SourceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Strict configuration for the complete catalog service.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CatalogConfig {
    /// Discovery sources and their public exposure rules.
    pub sources: Vec<CatalogSourceConfig>,
    /// Bounds applied to every refresh.
    pub refresh: RefreshConfig,
}

impl CatalogConfig {
    /// Validate and compile source rules and refresh limits.
    pub fn compile(self) -> Result<CompiledCatalogConfig, CatalogError> {
        let limits = self.refresh.compile()?;
        if self.sources.len() > limits.max_sources() {
            return Err(CatalogError::SourceLimitExceeded {
                actual: self.sources.len(),
                maximum: limits.max_sources(),
            });
        }

        let mut sources = self
            .sources
            .into_iter()
            .map(CatalogSourceConfig::compile)
            .collect::<Result<Vec<_>, _>>()?;
        sources.sort_by(source_order);
        let mut source_ids = BTreeSet::new();
        for source in &sources {
            if !source_ids.insert(source.id.clone()) {
                return Err(CatalogError::DuplicateSource {
                    source_id: source.id.clone(),
                });
            }
        }
        Ok(CompiledCatalogConfig { limits, sources })
    }
}

/// Strict rules for exposing one provider discovery source.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CatalogSourceConfig {
    /// Stable non-secret source ID.
    pub id: String,
    /// Provider that owns every discovered upstream model.
    pub provider: String,
    /// Optional client-visible namespace, emitted as `prefix/model`.
    pub prefix: Option<String>,
    /// Higher-priority targets are listed first.
    pub priority: i32,
    /// Exact upstream-name aliases.
    pub aliases: Vec<AliasConfig>,
    /// Case-sensitive exact or `*` wildcard allow-list, empty to include all.
    pub included_models: Vec<String>,
    /// Case-sensitive exact or `*` wildcard patterns evaluated upstream-first.
    pub excluded_models: Vec<String>,
}

impl CatalogSourceConfig {
    /// Validate and compile this source policy.
    pub fn compile(self) -> Result<CatalogSource, CatalogError> {
        let source = SourceId::new(self.id).map_err(|error| CatalogError::InvalidSourceId {
            message: error.to_string(),
        })?;
        let provider =
            ProviderId::new(self.provider).map_err(|error| CatalogError::InvalidProviderId {
                source_id: source.clone(),
                message: error.to_string(),
            })?;
        let prefix = self
            .prefix
            .map(|prefix| validate_prefix(&source, prefix))
            .transpose()?;

        if self.aliases.len() > MAX_ALIASES_PER_SOURCE {
            return Err(CatalogError::AliasLimitExceeded {
                source_id: source,
                actual: self.aliases.len(),
                maximum: MAX_ALIASES_PER_SOURCE,
            });
        }
        if self.included_models.len() > MAX_INCLUSIONS_PER_SOURCE {
            return Err(CatalogError::InclusionLimitExceeded {
                source_id: source,
                actual: self.included_models.len(),
                maximum: MAX_INCLUSIONS_PER_SOURCE,
            });
        }
        if self.excluded_models.len() > MAX_EXCLUSIONS_PER_SOURCE {
            return Err(CatalogError::ExclusionLimitExceeded {
                source_id: source,
                actual: self.excluded_models.len(),
                maximum: MAX_EXCLUSIONS_PER_SOURCE,
            });
        }

        let mut aliases = self
            .aliases
            .into_iter()
            .map(|alias| alias.compile(&source))
            .collect::<Result<Vec<_>, _>>()?;
        aliases.sort_by(|left, right| {
            left.public_id
                .cmp(&right.public_id)
                .then_with(|| left.upstream_id.cmp(&right.upstream_id))
        });
        for pair in aliases.windows(2) {
            if pair[0].public_id == pair[1].public_id {
                return Err(CatalogError::DuplicateAlias {
                    source_id: source,
                    alias: pair[0].public_id.clone(),
                });
            }
        }

        let inclusions = compile_patterns(&source, self.included_models, PatternKind::Inclusion)?;
        let exclusions = compile_patterns(&source, self.excluded_models, PatternKind::Exclusion)?;

        Ok(CatalogSource {
            id: source,
            provider,
            prefix,
            priority: self.priority,
            aliases,
            inclusions,
            exclusions,
        })
    }
}

/// One exact upstream-to-public model mapping.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AliasConfig {
    /// Upstream model ID.
    pub name: String,
    /// Client-visible model ID before the optional source prefix.
    pub alias: String,
    /// Preserve the unaliased model in addition to exposing the alias.
    pub fork: bool,
    /// Optional display name for the alias.
    pub display_name: Option<String>,
    /// Rewrite provider response model fields to the public ID.
    pub force_mapping: bool,
}

impl AliasConfig {
    fn compile(self, source: &SourceId) -> Result<CatalogAlias, CatalogError> {
        let upstream_id = ModelId::new(self.name).map_err(|error| CatalogError::InvalidAlias {
            source_id: source.clone(),
            message: format!("invalid upstream model: {error}"),
        })?;
        let public_id = ModelId::new(self.alias).map_err(|error| CatalogError::InvalidAlias {
            source_id: source.clone(),
            message: format!("invalid public model: {error}"),
        })?;
        if let Some(display_name) = &self.display_name {
            validate_display_name(source, display_name)?;
        }
        Ok(CatalogAlias {
            upstream_id,
            public_id,
            fork: self.fork,
            display_name: self.display_name,
            force_mapping: self.force_mapping,
        })
    }
}

/// Serializable refresh bounds.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RefreshConfig {
    /// Maximum complete refresh time in milliseconds.
    pub timeout_ms: u64,
    /// Maximum configured discovery sources.
    pub max_sources: usize,
    /// Maximum models returned by one source.
    pub max_models_per_source: usize,
    /// Maximum models returned across all sources.
    pub max_total_models: usize,
    /// Maximum simultaneous source calls.
    pub max_concurrency: usize,
    /// Maximum model/rule comparisons performed by a merge.
    pub max_merge_operations: usize,
}

impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_REFRESH_TIMEOUT_MS,
            max_sources: DEFAULT_MAX_SOURCES,
            max_models_per_source: DEFAULT_MAX_MODELS_PER_SOURCE,
            max_total_models: DEFAULT_MAX_TOTAL_MODELS,
            max_concurrency: DEFAULT_MAX_REFRESH_CONCURRENCY,
            max_merge_operations: DEFAULT_MAX_MERGE_OPERATIONS,
        }
    }
}

impl RefreshConfig {
    /// Validate configurable limits against non-disableable hard bounds.
    pub fn compile(self) -> Result<RefreshLimits, CatalogError> {
        validate_limit("max_sources", self.max_sources, HARD_MAX_SOURCES)?;
        validate_limit(
            "max_models_per_source",
            self.max_models_per_source,
            HARD_MAX_MODELS_PER_SOURCE,
        )?;
        validate_limit(
            "max_total_models",
            self.max_total_models,
            HARD_MAX_TOTAL_MODELS,
        )?;
        validate_limit(
            "max_concurrency",
            self.max_concurrency,
            HARD_MAX_REFRESH_CONCURRENCY,
        )?;
        validate_limit(
            "max_merge_operations",
            self.max_merge_operations,
            HARD_MAX_MERGE_OPERATIONS,
        )?;
        let timeout = Duration::from_millis(self.timeout_ms);
        if timeout.is_zero() || timeout > HARD_MAX_REFRESH_TIMEOUT {
            return Err(CatalogError::InvalidRefreshTimeout {
                actual_ms: self.timeout_ms,
                maximum_ms: duration_millis_u64(HARD_MAX_REFRESH_TIMEOUT),
            });
        }
        Ok(RefreshLimits {
            timeout,
            max_sources: self.max_sources,
            max_models_per_source: self.max_models_per_source,
            max_total_models: self.max_total_models,
            max_concurrency: self.max_concurrency,
            max_merge_operations: self.max_merge_operations,
        })
    }
}

/// Validated, non-disableable refresh bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshLimits {
    timeout: Duration,
    max_sources: usize,
    max_models_per_source: usize,
    max_total_models: usize,
    max_concurrency: usize,
    max_merge_operations: usize,
}

impl RefreshLimits {
    /// Complete refresh timeout.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Maximum discovery sources.
    #[must_use]
    pub const fn max_sources(self) -> usize {
        self.max_sources
    }

    /// Maximum models returned by one source.
    #[must_use]
    pub const fn max_models_per_source(self) -> usize {
        self.max_models_per_source
    }

    /// Maximum models returned by all sources.
    #[must_use]
    pub const fn max_total_models(self) -> usize {
        self.max_total_models
    }

    /// Maximum simultaneous discovery calls.
    #[must_use]
    pub const fn max_concurrency(self) -> usize {
        self.max_concurrency
    }

    /// Maximum model/rule comparisons performed by one merge.
    #[must_use]
    pub const fn max_merge_operations(self) -> usize {
        self.max_merge_operations
    }
}

/// Fully validated catalog configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledCatalogConfig {
    limits: RefreshLimits,
    sources: Vec<CatalogSource>,
}

impl CompiledCatalogConfig {
    /// Refresh bounds.
    #[must_use]
    pub const fn limits(&self) -> RefreshLimits {
        self.limits
    }

    /// Sources in deterministic priority order.
    #[must_use]
    pub fn sources(&self) -> &[CatalogSource] {
        &self.sources
    }
}

/// Validated public exposure rules for one discovery source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogSource {
    id: SourceId,
    provider: ProviderId,
    prefix: Option<String>,
    priority: i32,
    aliases: Vec<CatalogAlias>,
    inclusions: Vec<ModelPattern>,
    exclusions: Vec<ModelPattern>,
}

impl CatalogSource {
    /// Stable source ID.
    #[must_use]
    pub const fn id(&self) -> &SourceId {
        &self.id
    }

    /// Provider owning the upstream models.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Optional client-visible namespace.
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// Target ordering priority.
    #[must_use]
    pub const fn priority(&self) -> i32 {
        self.priority
    }

    /// Compiled upstream-to-public alias rules.
    #[must_use]
    pub fn aliases(&self) -> &[CatalogAlias] {
        &self.aliases
    }

    /// Upstream model allow-list patterns. Empty means all models are included.
    pub fn included_models(&self) -> impl Iterator<Item = &str> {
        self.inclusions.iter().map(ModelPattern::as_str)
    }

    /// Upstream model deny-list patterns.
    pub fn excluded_models(&self) -> impl Iterator<Item = &str> {
        self.exclusions.iter().map(ModelPattern::as_str)
    }
}

/// Validated upstream-to-public alias rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogAlias {
    upstream_id: ModelId,
    public_id: ModelId,
    fork: bool,
    display_name: Option<String>,
    force_mapping: bool,
}

impl CatalogAlias {
    /// Provider-native model ID matched by this rule.
    #[must_use]
    pub const fn upstream_id(&self) -> &ModelId {
        &self.upstream_id
    }

    /// Client-visible model ID before an optional source prefix.
    #[must_use]
    pub const fn public_id(&self) -> &ModelId {
        &self.public_id
    }

    /// Whether the native public ID remains visible beside the alias.
    #[must_use]
    pub const fn fork(&self) -> bool {
        self.fork
    }

    /// Alias-specific display name.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Whether provider response model fields must use the public ID.
    #[must_use]
    pub const fn force_mapping(&self) -> bool {
        self.force_mapping
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModelPattern {
    pattern: String,
}

impl ModelPattern {
    fn new(source: &SourceId, pattern: String, kind: PatternKind) -> Result<Self, CatalogError> {
        if pattern.is_empty()
            || pattern.len() > pooler_core::MAX_IDENTIFIER_LENGTH
            || pattern
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(kind.invalid(source.clone(), pattern));
        }
        Ok(Self { pattern })
    }

    fn as_str(&self) -> &str {
        &self.pattern
    }

    fn matches(&self, model: &str) -> bool {
        wildcard_matches(&self.pattern, model)
    }
}

#[derive(Clone, Copy)]
enum PatternKind {
    Inclusion,
    Exclusion,
}

impl PatternKind {
    fn invalid(self, source_id: SourceId, pattern: String) -> CatalogError {
        match self {
            Self::Inclusion => CatalogError::InvalidInclusion { source_id, pattern },
            Self::Exclusion => CatalogError::InvalidExclusion { source_id, pattern },
        }
    }

    fn duplicate(self, source_id: SourceId, pattern: String) -> CatalogError {
        match self {
            Self::Inclusion => CatalogError::DuplicateInclusion { source_id, pattern },
            Self::Exclusion => CatalogError::DuplicateExclusion { source_id, pattern },
        }
    }
}

fn compile_patterns(
    source: &SourceId,
    patterns: Vec<String>,
    kind: PatternKind,
) -> Result<Vec<ModelPattern>, CatalogError> {
    let mut patterns = patterns
        .into_iter()
        .map(|pattern| ModelPattern::new(source, pattern, kind))
        .collect::<Result<Vec<_>, _>>()?;
    patterns.sort_by(|left, right| left.pattern.cmp(&right.pattern));
    for pair in patterns.windows(2) {
        if pair[0].pattern == pair[1].pattern {
            return Err(kind.duplicate(source.clone(), pair[0].pattern.clone()));
        }
    }
    Ok(patterns)
}

/// Provider-returned metadata for one upstream model.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredModel {
    /// Provider-native upstream model ID.
    pub id: ModelId,
    /// Optional provider display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Capabilities proven by the provider adapter.
    #[serde(default)]
    pub capabilities: CapabilitySet,
}

impl DiscoveredModel {
    /// Construct the minimal discovery record.
    #[must_use]
    pub const fn new(id: ModelId, capabilities: CapabilitySet) -> Self {
        Self {
            id,
            display_name: None,
            capabilities,
        }
    }

    /// Attach a provider display name. It is validated before publication.
    #[must_use]
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }
}

/// One provider discovery response.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryResponse {
    /// Opaque provider revision or ETag suitable for diagnostics.
    pub revision: Option<String>,
    /// Discovered upstream models.
    pub models: Vec<DiscoveredModel>,
}

impl DiscoveryResponse {
    /// Construct a response without a provider revision.
    #[must_use]
    pub fn new(models: Vec<DiscoveredModel>) -> Self {
        Self {
            revision: None,
            models,
        }
    }

    /// Attach an opaque provider revision.
    #[must_use]
    pub fn with_revision(mut self, revision: impl Into<String>) -> Self {
        self.revision = Some(revision.into());
        self
    }
}

/// A source policy paired with one discovery response.
#[derive(Clone, Debug)]
pub struct CatalogInput {
    source: CatalogSource,
    response: DiscoveryResponse,
}

impl CatalogInput {
    /// Pair a compiled source with its provider response.
    #[must_use]
    pub const fn new(source: CatalogSource, response: DiscoveryResponse) -> Self {
        Self { source, response }
    }
}

/// How a discovered upstream model became client-visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureKind {
    /// Provider-native model name.
    Direct,
    /// Alias replaced the provider-native public name.
    Alias,
    /// Alias was added while retaining the provider-native public name.
    ForkedAlias,
}

/// Auditable origin for one public model target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModelProvenance {
    source: SourceId,
    provider: ProviderId,
    upstream_model: ModelId,
    revision: Option<String>,
    observed_at_unix_ms: u64,
    exposure: ExposureKind,
    prefix: Option<String>,
}

impl ModelProvenance {
    /// Discovery source.
    #[must_use]
    pub const fn source(&self) -> &SourceId {
        &self.source
    }

    /// Owning provider.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Provider-native model ID.
    #[must_use]
    pub const fn upstream_model(&self) -> &ModelId {
        &self.upstream_model
    }

    /// Opaque provider revision.
    #[must_use]
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    /// Caller-supplied observation time.
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// Exposure transformation.
    #[must_use]
    pub const fn exposure(&self) -> ExposureKind {
        self.exposure
    }

    /// Applied namespace prefix.
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
}

/// One provider/upstream routing target for a public model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogTarget {
    provider: ProviderId,
    upstream_model: ModelId,
    capabilities: CapabilitySet,
    force_mapping: bool,
    priority: i32,
    provenance: Vec<ModelProvenance>,
}

impl CatalogTarget {
    /// Target provider.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Provider-native model ID.
    #[must_use]
    pub const fn upstream_model(&self) -> &ModelId {
        &self.upstream_model
    }

    /// Capabilities common to all merged origins for this target.
    #[must_use]
    pub const fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    /// Whether response model fields must be rewritten to the public ID.
    #[must_use]
    pub const fn force_mapping(&self) -> bool {
        self.force_mapping
    }

    /// Target ordering priority.
    #[must_use]
    pub const fn priority(&self) -> i32 {
        self.priority
    }

    /// Every source that reported this target.
    #[must_use]
    pub fn provenance(&self) -> &[ModelProvenance] {
        &self.provenance
    }
}

/// One client-visible model in the merged catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogModel {
    id: ModelId,
    display_name: Option<String>,
    targets: Vec<CatalogTarget>,
}

impl CatalogModel {
    /// Client-visible model ID.
    #[must_use]
    pub const fn id(&self) -> &ModelId {
        &self.id
    }

    /// Deterministically selected display name.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Provider targets in deterministic priority order.
    #[must_use]
    pub fn targets(&self) -> &[CatalogTarget] {
        &self.targets
    }
}

/// Per-source counts and revision retained for management diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogSourceState {
    provider: ProviderId,
    revision: Option<String>,
    observed_at_unix_ms: u64,
    discovered_models: usize,
    not_included_models: usize,
    excluded_models: usize,
    published_exposures: usize,
}

impl CatalogSourceState {
    /// Provider owning this source.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Provider revision.
    #[must_use]
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    /// Caller-supplied observation time.
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// Models returned before exclusions.
    #[must_use]
    pub const fn discovered_models(&self) -> usize {
        self.discovered_models
    }

    /// Models omitted because they did not match the source allow-list.
    #[must_use]
    pub const fn not_included_models(&self) -> usize {
        self.not_included_models
    }

    /// Models removed by exclusion policy.
    #[must_use]
    pub const fn excluded_models(&self) -> usize {
        self.excluded_models
    }

    /// Public exposures produced after aliases and forks.
    #[must_use]
    pub const fn published_exposures(&self) -> usize {
        self.published_exposures
    }
}

/// Immutable merged catalog published to request and management paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogSnapshot {
    generation: u64,
    refreshed_at_unix_ms: u64,
    models: BTreeMap<ModelId, CatalogModel>,
    sources: BTreeMap<SourceId, CatalogSourceState>,
}

impl CatalogSnapshot {
    fn empty() -> Self {
        Self {
            generation: 0,
            refreshed_at_unix_ms: 0,
            models: BTreeMap::new(),
            sources: BTreeMap::new(),
        }
    }

    /// Monotonic successful-refresh generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Caller-supplied successful refresh time.
    #[must_use]
    pub const fn refreshed_at_unix_ms(&self) -> u64 {
        self.refreshed_at_unix_ms
    }

    /// Client-visible models in lexical ID order.
    #[must_use]
    pub const fn models(&self) -> &BTreeMap<ModelId, CatalogModel> {
        &self.models
    }

    /// Resolve one client-visible model.
    #[must_use]
    pub fn get(&self, model: &str) -> Option<&CatalogModel> {
        self.models.get(model)
    }

    /// Source states in lexical source-ID order.
    #[must_use]
    pub const fn sources(&self) -> &BTreeMap<SourceId, CatalogSourceState> {
        &self.sources
    }

    /// Number of provider/upstream targets across public models.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.models.values().map(|model| model.targets.len()).sum()
    }
}

/// Build a deterministic catalog from already-fetched provider responses.
///
/// Input ordering has no effect. Conflicting mappings for one public
/// model/provider pair are rejected rather than resolved by arrival order.
pub fn merge_discoveries(
    generation: u64,
    refreshed_at_unix_ms: u64,
    mut inputs: Vec<CatalogInput>,
    limits: RefreshLimits,
) -> Result<CatalogSnapshot, CatalogError> {
    if inputs.len() > limits.max_sources {
        return Err(CatalogError::SourceLimitExceeded {
            actual: inputs.len(),
            maximum: limits.max_sources,
        });
    }
    inputs.sort_by(|left, right| source_order(&left.source, &right.source));
    let mut seen_sources = BTreeSet::new();
    let mut total_models = 0usize;
    let mut merge_operations = 0usize;
    for input in &inputs {
        if !seen_sources.insert(input.source.id.clone()) {
            return Err(CatalogError::DuplicateSource {
                source_id: input.source.id.clone(),
            });
        }
        if input.response.models.len() > limits.max_models_per_source {
            return Err(CatalogError::SourceModelLimitExceeded {
                source_id: input.source.id.clone(),
                actual: input.response.models.len(),
                maximum: limits.max_models_per_source,
            });
        }
        total_models = total_models.saturating_add(input.response.models.len());
        if total_models > limits.max_total_models {
            return Err(CatalogError::TotalModelLimitExceeded {
                actual: total_models,
                maximum: limits.max_total_models,
            });
        }
        let rules_per_model = input
            .source
            .aliases
            .len()
            .saturating_add(input.source.inclusions.len())
            .saturating_add(input.source.exclusions.len())
            .saturating_add(1);
        merge_operations = merge_operations
            .saturating_add(input.response.models.len().saturating_mul(rules_per_model));
        if merge_operations > limits.max_merge_operations {
            return Err(CatalogError::MergeWorkLimitExceeded {
                actual: merge_operations,
                maximum: limits.max_merge_operations,
            });
        }
    }

    let mut candidates: BTreeMap<ModelId, Vec<Candidate>> = BTreeMap::new();
    let mut source_states = BTreeMap::new();
    for input in inputs {
        validate_revision(&input.source.id, input.response.revision.as_deref())?;
        let mut discovered = input.response.models;
        discovered.sort_by(|left, right| left.id.cmp(&right.id));
        for pair in discovered.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(CatalogError::DuplicateDiscoveredModel {
                    source_id: input.source.id.clone(),
                    model: pair[0].id.clone(),
                });
            }
        }

        let discovered_count = discovered.len();
        let mut not_included_count = 0usize;
        let mut excluded_count = 0usize;
        let mut exposure_count = 0usize;
        for model in discovered {
            if !input.source.inclusions.is_empty()
                && !input
                    .source
                    .inclusions
                    .iter()
                    .any(|pattern| pattern.matches(model.id.as_str()))
            {
                not_included_count += 1;
                continue;
            }
            if input
                .source
                .exclusions
                .iter()
                .any(|pattern| pattern.matches(model.id.as_str()))
            {
                excluded_count += 1;
                continue;
            }
            if let Some(display_name) = &model.display_name {
                validate_display_name(&input.source.id, display_name)?;
            }

            let matching_aliases = input
                .source
                .aliases
                .iter()
                .filter(|alias| alias.upstream_id == model.id)
                .collect::<Vec<_>>();
            if matching_aliases.is_empty() {
                push_candidate(
                    &mut candidates,
                    &input.source,
                    &input.response.revision,
                    refreshed_at_unix_ms,
                    &model,
                    &model.id,
                    model.display_name.clone(),
                    ExposureKind::Direct,
                    false,
                )?;
                exposure_count += 1;
                continue;
            }

            if matching_aliases.iter().any(|alias| alias.fork) {
                push_candidate(
                    &mut candidates,
                    &input.source,
                    &input.response.revision,
                    refreshed_at_unix_ms,
                    &model,
                    &model.id,
                    model.display_name.clone(),
                    ExposureKind::Direct,
                    false,
                )?;
                exposure_count += 1;
            }
            for alias in matching_aliases {
                push_candidate(
                    &mut candidates,
                    &input.source,
                    &input.response.revision,
                    refreshed_at_unix_ms,
                    &model,
                    &alias.public_id,
                    alias
                        .display_name
                        .clone()
                        .or_else(|| model.display_name.clone()),
                    if alias.fork {
                        ExposureKind::ForkedAlias
                    } else {
                        ExposureKind::Alias
                    },
                    alias.force_mapping,
                )?;
                exposure_count += 1;
            }
        }
        source_states.insert(
            input.source.id,
            CatalogSourceState {
                provider: input.source.provider,
                revision: input.response.revision,
                observed_at_unix_ms: refreshed_at_unix_ms,
                discovered_models: discovered_count,
                not_included_models: not_included_count,
                excluded_models: excluded_count,
                published_exposures: exposure_count,
            },
        );
    }

    let mut models = BTreeMap::new();
    for (public_id, public_candidates) in candidates {
        models.insert(
            public_id.clone(),
            compile_public_model(public_id, public_candidates)?,
        );
    }
    Ok(CatalogSnapshot {
        generation,
        refreshed_at_unix_ms,
        models,
        sources: source_states,
    })
}

#[derive(Clone, Debug)]
struct Candidate {
    display_name: Option<String>,
    provider: ProviderId,
    upstream_model: ModelId,
    capabilities: CapabilitySet,
    force_mapping: bool,
    priority: i32,
    provenance: ModelProvenance,
}

#[allow(clippy::too_many_arguments)]
fn push_candidate(
    candidates: &mut BTreeMap<ModelId, Vec<Candidate>>,
    source: &CatalogSource,
    revision: &Option<String>,
    observed_at_unix_ms: u64,
    model: &DiscoveredModel,
    unprefixed_public_id: &ModelId,
    display_name: Option<String>,
    exposure: ExposureKind,
    force_mapping: bool,
) -> Result<(), CatalogError> {
    let public_id = prefixed_model_id(source, unprefixed_public_id)?;
    candidates.entry(public_id).or_default().push(Candidate {
        display_name,
        provider: source.provider.clone(),
        upstream_model: model.id.clone(),
        capabilities: model.capabilities,
        force_mapping,
        priority: source.priority,
        provenance: ModelProvenance {
            source: source.id.clone(),
            provider: source.provider.clone(),
            upstream_model: model.id.clone(),
            revision: revision.clone(),
            observed_at_unix_ms,
            exposure,
            prefix: source.prefix.clone(),
        },
    });
    Ok(())
}

fn compile_public_model(
    public_id: ModelId,
    mut candidates: Vec<Candidate>,
) -> Result<CatalogModel, CatalogError> {
    candidates.sort_by(candidate_order);
    let display_name = candidates
        .iter()
        .find_map(|candidate| candidate.display_name.clone());
    let mut targets: Vec<CatalogTarget> = Vec::new();
    let mut provider_mappings: BTreeMap<ProviderId, (ModelId, SourceId)> = BTreeMap::new();

    for candidate in candidates {
        if let Some((upstream, first_source)) = provider_mappings.get(&candidate.provider) {
            if upstream != &candidate.upstream_model {
                return Err(CatalogError::ConflictingPublicMapping {
                    conflict: Box::new(PublicMappingConflict {
                        public_model: public_id,
                        provider: candidate.provider,
                        first_upstream: upstream.clone(),
                        first_source: first_source.clone(),
                        second_upstream: candidate.upstream_model,
                        second_source: candidate.provenance.source,
                    }),
                });
            }
        } else {
            provider_mappings.insert(
                candidate.provider.clone(),
                (
                    candidate.upstream_model.clone(),
                    candidate.provenance.source.clone(),
                ),
            );
        }

        if let Some(target) = targets.iter_mut().find(|target| {
            target.provider == candidate.provider
                && target.upstream_model == candidate.upstream_model
        }) {
            target.capabilities = target.capabilities.intersection(candidate.capabilities);
            target.force_mapping |= candidate.force_mapping;
            target.priority = target.priority.max(candidate.priority);
            target.provenance.push(candidate.provenance);
        } else {
            targets.push(CatalogTarget {
                provider: candidate.provider,
                upstream_model: candidate.upstream_model,
                capabilities: candidate.capabilities,
                force_mapping: candidate.force_mapping,
                priority: candidate.priority,
                provenance: vec![candidate.provenance],
            });
        }
    }

    for target in &mut targets {
        target.provenance.sort_by(provenance_order);
    }
    targets.sort_by(target_order);
    Ok(CatalogModel {
        id: public_id,
        display_name,
        targets,
    })
}

fn prefixed_model_id(source: &CatalogSource, public_id: &ModelId) -> Result<ModelId, CatalogError> {
    let Some(prefix) = &source.prefix else {
        return Ok(public_id.clone());
    };
    ModelId::new(format!("{prefix}/{public_id}")).map_err(|error| {
        CatalogError::PrefixedModelInvalid {
            source_id: source.id.clone(),
            model: public_id.clone(),
            message: error.to_string(),
        }
    })
}

/// Stable, non-secret failure categories accepted at the discovery boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryFailureKind {
    /// The provider could not be reached or did not complete in time.
    Transport,
    /// Configured authentication was unavailable or rejected.
    Authentication,
    /// The provider returned an unsuccessful response.
    Provider,
    /// The provider response did not match the selected bounded parser.
    InvalidResponse,
    /// A response or parser resource bound was exceeded.
    LimitExceeded,
    /// Runtime shutdown cancelled the discovery attempt.
    Cancelled,
    /// An internal integration invariant failed.
    Internal,
}

impl Display for DiscoveryFailureKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Transport => "transport",
            Self::Authentication => "authentication",
            Self::Provider => "provider",
            Self::InvalidResponse => "invalid_response",
            Self::LimitExceeded => "limit_exceeded",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal",
        })
    }
}

/// A centrally redacted provider discovery failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("model discovery failed ({kind})")]
pub struct DiscoveryFailure {
    kind: DiscoveryFailureKind,
}

impl DiscoveryFailure {
    /// Construct a provider failure while discarding caller-supplied text.
    ///
    /// This compatibility constructor deliberately ignores `message`; use
    /// [`Self::from_kind`] when the integration can classify the failure.
    #[must_use]
    pub fn new(_message: impl AsRef<str>) -> Self {
        Self::from_kind(DiscoveryFailureKind::Provider)
    }

    /// Construct from a stable failure category.
    #[must_use]
    pub const fn from_kind(kind: DiscoveryFailureKind) -> Self {
        Self { kind }
    }

    /// Stable failure category.
    #[must_use]
    pub const fn kind(self) -> DiscoveryFailureKind {
        self.kind
    }
}

/// Boxed discovery future used without an async-trait macro.
pub type DiscoveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DiscoveryResponse, DiscoveryFailure>> + Send + 'a>>;

/// Provider-specific model discovery boundary.
pub trait ModelDiscovery: Send + Sync {
    /// Fetch the provider's current model list.
    fn discover(&self) -> DiscoveryFuture<'_>;
}

/// One compiled source registered with its provider discovery implementation.
#[derive(Clone)]
pub struct RegisteredSource {
    source: CatalogSource,
    discovery: Arc<dyn ModelDiscovery>,
}

impl RegisteredSource {
    /// Register a discovery implementation for a compiled source policy.
    #[must_use]
    pub fn new(source: CatalogSource, discovery: Arc<dyn ModelDiscovery>) -> Self {
        Self { source, discovery }
    }

    /// Compiled source policy.
    #[must_use]
    pub const fn source(&self) -> &CatalogSource {
        &self.source
    }
}

impl fmt::Debug for RegisteredSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredSource")
            .field("source", &self.source)
            .field("discovery", &"<model-discovery>")
            .finish()
    }
}

/// Atomically published model catalog with serialized, bounded refreshes.
pub struct CatalogService {
    sources: Vec<RegisteredSource>,
    limits: RefreshLimits,
    snapshot: ArcSwap<CatalogSnapshot>,
    refresh_gate: Arc<Semaphore>,
}

impl CatalogService {
    /// Create a service from explicitly registered sources.
    pub fn new(
        mut sources: Vec<RegisteredSource>,
        limits: RefreshLimits,
    ) -> Result<Self, CatalogError> {
        if sources.len() > limits.max_sources {
            return Err(CatalogError::SourceLimitExceeded {
                actual: sources.len(),
                maximum: limits.max_sources,
            });
        }
        sources.sort_by(|left, right| source_order(&left.source, &right.source));
        let mut source_ids = BTreeSet::new();
        for registered in &sources {
            if !source_ids.insert(registered.source.id.clone()) {
                return Err(CatalogError::DuplicateSource {
                    source_id: registered.source.id.clone(),
                });
            }
        }
        Ok(Self {
            sources,
            limits,
            snapshot: ArcSwap::from_pointee(CatalogSnapshot::empty()),
            refresh_gate: Arc::new(Semaphore::new(1)),
        })
    }

    /// Load the immutable current snapshot without blocking refresh work.
    #[must_use]
    pub fn snapshot(&self) -> Arc<CatalogSnapshot> {
        self.snapshot.load_full()
    }

    /// Refresh all sources and atomically publish only a complete valid result.
    ///
    /// `observed_at_unix_ms` comes from the caller so tests and replay retain a
    /// deterministic clock boundary. Concurrent refresh calls fail fast.
    pub async fn refresh(&self, observed_at_unix_ms: u64) -> Result<RefreshReport, CatalogError> {
        let _refresh_permit = self
            .refresh_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| CatalogError::RefreshInProgress)?;
        let deadline = tokio::time::Instant::now() + self.limits.timeout;
        let concurrency = self.limits.max_concurrency.min(self.sources.len().max(1));
        let fetches = stream::iter(self.sources.iter().cloned())
            .map(|registered| async move {
                let response = registered.discovery.discover().await;
                (registered.source, response)
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>();
        let mut responses = tokio::time::timeout_at(deadline, fetches)
            .await
            .map_err(|_| CatalogError::RefreshTimedOut {
                timeout_ms: duration_millis_u64(self.limits.timeout),
            })?;
        responses.sort_by(|left, right| source_order(&left.0, &right.0));

        let mut inputs = Vec::with_capacity(responses.len());
        for (source, response) in responses {
            let response = response.map_err(|failure| CatalogError::DiscoveryFailed {
                source_id: source.id.clone(),
                kind: failure.kind(),
            })?;
            inputs.push(CatalogInput::new(source, response));
        }

        let previous = self.snapshot.load_full();
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(CatalogError::GenerationExhausted)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(CatalogError::RefreshTimedOut {
                timeout_ms: duration_millis_u64(self.limits.timeout),
            });
        }
        let limits = self.limits;
        let merge = tokio::task::spawn_blocking(move || {
            merge_discoveries(generation, observed_at_unix_ms, inputs, limits)
        });
        let candidate = tokio::time::timeout_at(deadline, merge)
            .await
            .map_err(|_| CatalogError::RefreshTimedOut {
                timeout_ms: duration_millis_u64(self.limits.timeout),
            })?
            .map_err(|_| CatalogError::MergeWorkerFailed)??;
        let report = RefreshReport {
            generation,
            source_count: candidate.sources.len(),
            model_count: candidate.models.len(),
            target_count: candidate.target_count(),
        };
        self.snapshot.store(Arc::new(candidate));
        Ok(report)
    }
}

impl fmt::Debug for CatalogService {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogService")
            .field("sources", &self.sources)
            .field("limits", &self.limits)
            .field("generation", &self.snapshot.load().generation)
            .finish_non_exhaustive()
    }
}

/// Counts from one successfully published refresh.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RefreshReport {
    generation: u64,
    source_count: usize,
    model_count: usize,
    target_count: usize,
}

impl RefreshReport {
    /// Published generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Refreshed sources.
    #[must_use]
    pub const fn source_count(self) -> usize {
        self.source_count
    }

    /// Published public models.
    #[must_use]
    pub const fn model_count(self) -> usize {
        self.model_count
    }

    /// Published provider targets.
    #[must_use]
    pub const fn target_count(self) -> usize {
        self.target_count
    }
}

/// Deterministic details for an ambiguous public/provider mapping.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error(
    "public model {public_model} maps provider {provider} to both {first_upstream} ({first_source}) and {second_upstream} ({second_source})"
)]
pub struct PublicMappingConflict {
    public_model: ModelId,
    provider: ProviderId,
    first_upstream: ModelId,
    first_source: SourceId,
    second_upstream: ModelId,
    second_source: SourceId,
}

impl PublicMappingConflict {
    /// Ambiguous client-visible model ID.
    #[must_use]
    pub const fn public_model(&self) -> &ModelId {
        &self.public_model
    }

    /// Provider whose upstream mapping is ambiguous.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Higher-priority deterministic mapping.
    #[must_use]
    pub const fn first_upstream(&self) -> &ModelId {
        &self.first_upstream
    }

    /// Source of the higher-priority mapping.
    #[must_use]
    pub const fn first_source(&self) -> &SourceId {
        &self.first_source
    }

    /// Conflicting lower-priority mapping.
    #[must_use]
    pub const fn second_upstream(&self) -> &ModelId {
        &self.second_upstream
    }

    /// Source of the conflicting lower-priority mapping.
    #[must_use]
    pub const fn second_source(&self) -> &SourceId {
        &self.second_source
    }
}

/// Catalog configuration, merge, or refresh failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CatalogError {
    /// Invalid source identifier.
    #[error("invalid catalog source id: {message}")]
    InvalidSourceId { message: String },
    /// Invalid provider identifier.
    #[error("catalog source {source_id} has an invalid provider id: {message}")]
    InvalidProviderId {
        source_id: SourceId,
        message: String,
    },
    /// Invalid source prefix.
    #[error("catalog source {source_id} has invalid prefix {prefix:?}")]
    InvalidPrefix { source_id: SourceId, prefix: String },
    /// Invalid alias declaration.
    #[error("catalog source {source_id} has an invalid alias: {message}")]
    InvalidAlias {
        source_id: SourceId,
        message: String,
    },
    /// Duplicate public alias in one source.
    #[error("catalog source {source_id} declares public alias {alias} more than once")]
    DuplicateAlias { source_id: SourceId, alias: ModelId },
    /// Too many aliases in one source.
    #[error("catalog source {source_id} has {actual} aliases; maximum is {maximum}")]
    AliasLimitExceeded {
        source_id: SourceId,
        actual: usize,
        maximum: usize,
    },
    /// Invalid inclusion wildcard.
    #[error("catalog source {source_id} has invalid inclusion pattern {pattern:?}")]
    InvalidInclusion {
        source_id: SourceId,
        pattern: String,
    },
    /// Duplicate inclusion wildcard.
    #[error("catalog source {source_id} repeats inclusion pattern {pattern:?}")]
    DuplicateInclusion {
        source_id: SourceId,
        pattern: String,
    },
    /// Too many inclusions in one source.
    #[error("catalog source {source_id} has {actual} inclusions; maximum is {maximum}")]
    InclusionLimitExceeded {
        source_id: SourceId,
        actual: usize,
        maximum: usize,
    },
    /// Invalid exclusion wildcard.
    #[error("catalog source {source_id} has invalid exclusion pattern {pattern:?}")]
    InvalidExclusion {
        source_id: SourceId,
        pattern: String,
    },
    /// Duplicate exclusion wildcard.
    #[error("catalog source {source_id} repeats exclusion pattern {pattern:?}")]
    DuplicateExclusion {
        source_id: SourceId,
        pattern: String,
    },
    /// Too many exclusions in one source.
    #[error("catalog source {source_id} has {actual} exclusions; maximum is {maximum}")]
    ExclusionLimitExceeded {
        source_id: SourceId,
        actual: usize,
        maximum: usize,
    },
    /// Invalid display metadata.
    #[error("catalog source {source_id} returned an invalid model display name")]
    InvalidDisplayName { source_id: SourceId },
    /// Invalid provider revision metadata.
    #[error("catalog source {source_id} returned an invalid catalog revision")]
    InvalidRevision { source_id: SourceId },
    /// Invalid numeric refresh bound.
    #[error("invalid refresh limit {field}={actual}; expected 1..={maximum}")]
    InvalidRefreshLimit {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    /// Invalid refresh timeout.
    #[error("invalid refresh timeout {actual_ms}ms; expected 1..={maximum_ms}ms")]
    InvalidRefreshTimeout { actual_ms: u64, maximum_ms: u64 },
    /// Too many discovery sources.
    #[error("catalog has {actual} sources; maximum is {maximum}")]
    SourceLimitExceeded { actual: usize, maximum: usize },
    /// Duplicate source registration or merge input.
    #[error("catalog source {source_id} is registered more than once")]
    DuplicateSource { source_id: SourceId },
    /// Duplicate model ID in one provider response.
    #[error("catalog source {source_id} returned model {model} more than once")]
    DuplicateDiscoveredModel { source_id: SourceId, model: ModelId },
    /// One provider response exceeded its model bound.
    #[error("catalog source {source_id} returned {actual} models; maximum is {maximum}")]
    SourceModelLimitExceeded {
        source_id: SourceId,
        actual: usize,
        maximum: usize,
    },
    /// The aggregate response exceeded its model bound.
    #[error("catalog refresh returned {actual} models; maximum is {maximum}")]
    TotalModelLimitExceeded { actual: usize, maximum: usize },
    /// Alias/filter evaluation exceeded the configured deterministic work budget.
    #[error("catalog merge requires {actual} operations; maximum is {maximum}")]
    MergeWorkLimitExceeded { actual: usize, maximum: usize },
    /// Prefixing produced an invalid public model ID.
    #[error("catalog source {source_id} cannot prefix model {model}: {message}")]
    PrefixedModelInvalid {
        source_id: SourceId,
        model: ModelId,
        message: String,
    },
    /// One public/provider pair mapped to multiple upstream names.
    #[error("{conflict}")]
    ConflictingPublicMapping {
        /// Structured conflict details.
        conflict: Box<PublicMappingConflict>,
    },
    /// A refresh is already active.
    #[error("model catalog refresh is already in progress")]
    RefreshInProgress,
    /// Complete refresh deadline elapsed.
    #[error("model catalog refresh exceeded {timeout_ms}ms")]
    RefreshTimedOut { timeout_ms: u64 },
    /// Provider discovery failed.
    #[error("model discovery from {source_id} failed ({kind})")]
    DiscoveryFailed {
        source_id: SourceId,
        kind: DiscoveryFailureKind,
    },
    /// The isolated merge worker failed without publishing a candidate.
    #[error("model catalog merge worker failed")]
    MergeWorkerFailed,
    /// The successful-refresh generation cannot advance.
    #[error("model catalog generation is exhausted")]
    GenerationExhausted,
}

fn source_order(left: &CatalogSource, right: &CatalogSource) -> std::cmp::Ordering {
    right
        .priority
        .cmp(&left.priority)
        .then_with(|| left.id.cmp(&right.id))
}

fn candidate_order(left: &Candidate, right: &Candidate) -> std::cmp::Ordering {
    right
        .priority
        .cmp(&left.priority)
        .then_with(|| left.provenance.source.cmp(&right.provenance.source))
        .then_with(|| left.provider.cmp(&right.provider))
        .then_with(|| left.upstream_model.cmp(&right.upstream_model))
}

fn target_order(left: &CatalogTarget, right: &CatalogTarget) -> std::cmp::Ordering {
    right
        .priority
        .cmp(&left.priority)
        .then_with(|| left.provider.cmp(&right.provider))
        .then_with(|| left.upstream_model.cmp(&right.upstream_model))
}

fn provenance_order(left: &ModelProvenance, right: &ModelProvenance) -> std::cmp::Ordering {
    left.source
        .cmp(&right.source)
        .then_with(|| left.upstream_model.cmp(&right.upstream_model))
        .then_with(|| exposure_rank(left.exposure).cmp(&exposure_rank(right.exposure)))
}

const fn exposure_rank(exposure: ExposureKind) -> u8 {
    match exposure {
        ExposureKind::Direct => 0,
        ExposureKind::Alias => 1,
        ExposureKind::ForkedAlias => 2,
    }
}

fn validate_limit(field: &'static str, actual: usize, maximum: usize) -> Result<(), CatalogError> {
    if actual == 0 || actual > maximum {
        Err(CatalogError::InvalidRefreshLimit {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn validate_prefix(source: &SourceId, prefix: String) -> Result<String, CatalogError> {
    let invalid = prefix.is_empty()
        || prefix.len() > pooler_core::MAX_IDENTIFIER_LENGTH
        || prefix.starts_with('/')
        || prefix.ends_with('/')
        || prefix.contains('*')
        || prefix
            .chars()
            .any(|character| character.is_control() || character.is_whitespace());
    if invalid {
        Err(CatalogError::InvalidPrefix {
            source_id: source.clone(),
            prefix,
        })
    } else {
        Ok(prefix)
    }
}

fn validate_display_name(source: &SourceId, display_name: &str) -> Result<(), CatalogError> {
    if display_name.is_empty()
        || display_name.len() > MAX_DISPLAY_NAME_BYTES
        || display_name.chars().any(char::is_control)
    {
        Err(CatalogError::InvalidDisplayName {
            source_id: source.clone(),
        })
    } else {
        Ok(())
    }
}

fn validate_revision(source: &SourceId, revision: Option<&str>) -> Result<(), CatalogError> {
    if revision.is_some_and(|revision| {
        revision.is_empty()
            || revision.len() > MAX_REVISION_BYTES
            || revision.chars().any(char::is_control)
    }) {
        Err(CatalogError::InvalidRevision {
            source_id: source.clone(),
        })
    } else {
        Ok(())
    }
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0usize, 0usize);
    let (mut star_index, mut star_value_index) = (None, 0usize);

    while value_index < value.len() {
        if pattern.get(pattern_index) == value.get(value_index) {
            pattern_index += 1;
            value_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'*') {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::wildcard_matches;

    #[test]
    fn exclusion_glob_supports_exact_prefix_suffix_and_substring() {
        assert!(wildcard_matches("gemini-2.5-pro", "gemini-2.5-pro"));
        assert!(wildcard_matches("gemini-2.5-*", "gemini-2.5-flash"));
        assert!(wildcard_matches("*-preview", "gemini-pro-preview"));
        assert!(wildcard_matches("*flash*", "gemini-flash-lite"));
        assert!(wildcard_matches("*", "anything"));
        assert!(!wildcard_matches("gpt-5-*", "gpt-4.1"));
        assert!(!wildcard_matches("*-preview", "preview-model"));
    }
}
