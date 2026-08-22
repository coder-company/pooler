//! File imports and deterministic overlay resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pooler_model_catalog::ProviderCatalog;
use serde::Deserialize;
use serde_yml::{Mapping, Value};

use crate::{validate_version, Config, ConfigError, Source, SourceLabel};

struct ResolvedDocument {
    value: Value,
    origins: BTreeMap<String, Arc<str>>,
    dependencies: BTreeSet<PathBuf>,
}

/// A parsed configuration together with every file that contributed to it.
///
/// The dependency list is canonical and deterministic.  Callers that watch a
/// configuration can therefore include imported files and overlays without
/// reimplementing the resolver's relative-path or preset rules.
#[derive(Clone, Debug)]
pub struct LoadedConfig {
    config: Config,
    root: PathBuf,
    dependencies: Arc<[PathBuf]>,
    rendered: Arc<str>,
}

impl LoadedConfig {
    /// Parsed source configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Canonical root file used to load this configuration.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Canonical files that contributed to this configuration.
    #[must_use]
    pub fn dependencies(&self) -> &[PathBuf] {
        &self.dependencies
    }

    /// Deterministic expanded representation used for no-op comparisons.
    #[must_use]
    pub fn rendered(&self) -> &str {
        &self.rendered
    }

    /// Compile the parsed source with a caller-owned generation.
    pub fn compile_with_generation(
        &self,
        generation: u64,
    ) -> Result<crate::CompiledConfig, ConfigError> {
        self.config.compile_with_generation(generation)
    }

    /// Compile the parsed source with generation one.
    pub fn compile(&self) -> Result<crate::CompiledConfig, ConfigError> {
        self.config.compile()
    }
}

/// Default maximum nested import depth.
pub const DEFAULT_MAX_IMPORT_DEPTH: usize = 16;

/// Every preset `expand_preset` accepts, in the order the error message lists
/// them. The configuration schema publishes this same list, so a preset can
/// never be loadable but unrepresentable in the schema, or the reverse.
pub(crate) const SUPPORTED_PRESETS: [&str; 7] = [
    "cursor", "devin", "factory", "fx", "gateway", "media", "xai",
];

/// Loads and resolves configuration files.
#[derive(Clone, Debug)]
pub struct ConfigLoader {
    max_import_depth: usize,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self {
            max_import_depth: DEFAULT_MAX_IMPORT_DEPTH,
        }
    }
}

impl ConfigLoader {
    /// Create a loader with an explicit import-depth bound.
    #[must_use]
    pub const fn new(max_import_depth: usize) -> Self {
        Self { max_import_depth }
    }

    /// Resolve and parse a configuration file.
    pub fn load(&self, path: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|error| ConfigError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        let has_imports = serde_yml::from_str::<Value>(&raw)
            .ok()
            .is_some_and(|value| {
                value.as_mapping().is_some_and(|mapping| {
                    mapping.contains_key(Value::String("imports".to_owned()))
                })
            });
        if !has_imports {
            return Config::from_yaml(path.display().to_string(), &raw);
        }
        let resolved = self.resolve(path)?;
        let rendered = render_value(&resolved.value, path)?;
        parse_resolved(path, &rendered, &resolved)
    }

    /// Load a configuration and retain its canonical dependency set.
    ///
    /// This method deliberately resolves even a file without imports. The
    /// regular [`Self::load`] fast path retains parser coordinates for the
    /// common case; reload watchers need the dependency graph as well.
    pub fn load_tracked(&self, path: impl AsRef<Path>) -> Result<LoadedConfig, ConfigError> {
        let root = std::fs::canonicalize(path.as_ref()).map_err(|error| ConfigError::Io {
            path: path.as_ref().display().to_string(),
            message: error.to_string(),
        })?;
        let resolved = self.resolve(&root)?;
        let rendered = render_value(&resolved.value, &root)?;
        let config = parse_resolved(&root, &rendered, &resolved)?;
        let dependencies = resolved.dependencies.into_iter().collect::<Vec<_>>();
        Ok(LoadedConfig {
            config,
            root,
            dependencies: Arc::from(dependencies),
            rendered: Arc::from(rendered),
        })
    }

    /// Resolve a configuration file to deterministic expanded YAML.
    pub fn render(&self, path: impl AsRef<Path>) -> Result<String, ConfigError> {
        let path = path.as_ref();
        render_value(&self.resolve(path)?.value, path)
    }

    fn resolve(&self, path: &Path) -> Result<ResolvedDocument, ConfigError> {
        let mut stack = Vec::new();
        self.resolve_inner(path, &mut stack)
    }

    fn resolve_inner(
        &self,
        path: &Path,
        stack: &mut Vec<PathBuf>,
    ) -> Result<ResolvedDocument, ConfigError> {
        if stack.len() > self.max_import_depth {
            return Err(load_error(
                path,
                "maximum configuration import depth exceeded",
            ));
        }
        let canonical = std::fs::canonicalize(path).map_err(|error| ConfigError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        if stack.contains(&canonical) {
            let mut chain: Vec<_> = stack
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            chain.push(canonical.display().to_string());
            return Err(load_error(
                path,
                &format!("configuration import cycle: {}", chain.join(" -> ")),
            ));
        }
        stack.push(canonical.clone());

        let text = std::fs::read_to_string(&canonical).map_err(|error| ConfigError::Io {
            path: canonical.display().to_string(),
            message: error.to_string(),
        })?;
        let mut document: Value =
            serde_yml::from_str(&text).map_err(|error| ConfigError::Parse {
                source_name: canonical.display().to_string(),
                line: error
                    .location()
                    .as_ref()
                    .map_or(1, serde_yml::Location::line),
                column: error
                    .location()
                    .as_ref()
                    .map_or(1, serde_yml::Location::column),
                message: error
                    .to_string()
                    .lines()
                    .next()
                    .unwrap_or("invalid YAML")
                    .to_owned(),
            })?;
        normalize_provider_alias(&mut document, &canonical)?;
        let imports = take_imports(&mut document, &canonical)?;
        let document_origins = collect_origins(&document, &canonical);
        let parent = canonical.parent().unwrap_or_else(|| Path::new("."));

        let mut resolved = ResolvedDocument {
            value: Value::Mapping(Mapping::new()),
            origins: BTreeMap::new(),
            dependencies: BTreeSet::from([canonical.clone()]),
        };
        for import in imports.iter().filter(|import| import.overlay.is_none()) {
            let (imported, additive_sequences) = if let Some(file) = &import.file {
                (self.resolve_inner(&parent.join(file), stack)?, false)
            } else {
                let value = expand_preset(import, &canonical)?;
                let mut origins = collect_origins(&value, &canonical);
                let preset_source: Arc<str> = Arc::from(format!(
                    "preset:{} ({})",
                    import.preset.as_deref().unwrap_or("unknown"),
                    canonical.display()
                ));
                for origin in origins.values_mut() {
                    *origin = Arc::clone(&preset_source);
                }
                (
                    ResolvedDocument {
                        origins,
                        value,
                        dependencies: BTreeSet::from([canonical.clone()]),
                    },
                    true,
                )
            };
            merge_resolved(&mut resolved, imported, &canonical, additive_sequences)?;
        }
        merge_resolved(
            &mut resolved,
            ResolvedDocument {
                value: document,
                origins: document_origins,
                dependencies: BTreeSet::from([canonical.clone()]),
            },
            &canonical,
            false,
        )?;
        for import in imports.iter().filter(|import| import.overlay.is_some()) {
            let overlay =
                self.read_overlay(&parent.join(import.overlay.as_ref().unwrap()), stack)?;
            merge_resolved(&mut resolved, overlay, &canonical, false)?;
        }
        stack.pop();
        Ok(resolved)
    }

    fn read_overlay(
        &self,
        path: &Path,
        stack: &[PathBuf],
    ) -> Result<ResolvedDocument, ConfigError> {
        let canonical = std::fs::canonicalize(path).map_err(|error| ConfigError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        if stack.contains(&canonical) {
            return Err(load_error(path, "configuration import cycle"));
        }
        let text = std::fs::read_to_string(&canonical).map_err(|error| ConfigError::Io {
            path: canonical.display().to_string(),
            message: error.to_string(),
        })?;
        let mut document: Value =
            serde_yml::from_str(&text).map_err(|error| ConfigError::Parse {
                source_name: canonical.display().to_string(),
                line: error
                    .location()
                    .as_ref()
                    .map_or(1, serde_yml::Location::line),
                column: error
                    .location()
                    .as_ref()
                    .map_or(1, serde_yml::Location::column),
                message: error
                    .to_string()
                    .lines()
                    .next()
                    .unwrap_or("invalid YAML")
                    .to_owned(),
            })?;
        normalize_provider_alias(&mut document, &canonical)?;
        if !take_imports(&mut document, &canonical)?.is_empty() {
            return Err(load_error(
                &canonical,
                "overlay files cannot contain nested imports",
            ));
        }
        Ok(ResolvedDocument {
            origins: collect_origins(&document, &canonical),
            value: document,
            dependencies: BTreeSet::from([canonical]),
        })
    }
}

fn parse_resolved(
    root: &Path,
    rendered: &str,
    resolved: &ResolvedDocument,
) -> Result<Config, ConfigError> {
    let deserializer = serde_yml::Deserializer::from_str(rendered);
    let mut config: Config = serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let field_path = error.path().to_string();
        let origin_key = origin_key_for_path(&field_path, &resolved.value, &resolved.origins);
        let source = origin_key
            .as_deref()
            .and_then(|key| resolved.origins.get(key))
            .cloned()
            .unwrap_or_else(|| Arc::from(root.display().to_string()));
        ConfigError::Invalid {
            label: SourceLabel {
                source,
                line: None,
                column: None,
                path: Arc::from(field_path),
            },
            message: error
                .inner()
                .to_string()
                .lines()
                .next()
                .unwrap_or("invalid configuration")
                .to_owned(),
        }
    })?;
    let source = Source::new(root.display().to_string(), rendered);
    validate_version(&config, &source)?;
    config.source = Some(source);
    config.set_origins(resolved.origins.clone());
    Ok(config)
}

fn origin_key_for_path(
    path: &str,
    document: &Value,
    origins: &BTreeMap<String, Arc<str>>,
) -> Option<String> {
    if let Some(key) = origins
        .keys()
        .filter(|key| path == key.as_str() || path.starts_with(&format!("{key}.")))
        .max_by_key(|key| key.len())
    {
        return Some(key.clone());
    }
    for section in ["routes", "models"] {
        let prefix = format!("{section}[");
        let Some(rest) = path.strip_prefix(&prefix) else {
            continue;
        };
        let (index, _) = rest.split_once(']')?;
        let index: usize = index.parse().ok()?;
        let id = document
            .as_mapping()?
            .get(Value::String(section.to_owned()))?
            .as_sequence()?
            .get(index)
            .and_then(|value| declaration_id(value, Path::new("<resolved>")).ok())?;
        return Some(format!("{section}.{id}"));
    }
    None
}

/// Resolve and parse a configuration file with default limits.
pub fn load_path(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    ConfigLoader::default().load(path)
}

/// Render deterministic expanded YAML with default limits.
pub fn render_path(path: impl AsRef<Path>) -> Result<String, ConfigError> {
    ConfigLoader::default().render(path)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportSpec {
    file: Option<PathBuf>,
    overlay: Option<PathBuf>,
    preset: Option<String>,
    #[serde(rename = "as")]
    alias: Option<String>,
    #[serde(rename = "with", default)]
    parameters: BTreeMap<String, Value>,
}

fn take_imports(document: &mut Value, path: &Path) -> Result<Vec<ImportSpec>, ConfigError> {
    let mapping = document
        .as_mapping_mut()
        .ok_or_else(|| load_error(path, "configuration root must be a mapping"))?;
    let Some(value) = mapping.remove(Value::String("imports".to_owned())) else {
        return Ok(Vec::new());
    };
    let imports: Vec<ImportSpec> = serde_yml::from_value(value)
        .map_err(|error| load_error(path, &format!("invalid imports: {error}")))?;
    for import in &imports {
        if usize::from(import.file.is_some())
            + usize::from(import.overlay.is_some())
            + usize::from(import.preset.is_some())
            != 1
        {
            return Err(load_error(
                path,
                "each import must contain exactly one of file, overlay, or preset",
            ));
        }
        if import.preset.is_none() && (import.alias.is_some() || !import.parameters.is_empty()) {
            return Err(load_error(
                path,
                "as/with are only valid for preset imports",
            ));
        }
    }
    Ok(imports)
}

fn expand_preset(import: &ImportSpec, path: &Path) -> Result<Value, ConfigError> {
    match import.preset.as_deref() {
        Some("cursor") => expand_cursor_preset(import, path),
        Some("devin") => expand_devin_preset(import, path),
        Some("factory") => expand_factory_preset(import, path),
        Some("fx") => expand_fx_preset(import, path),
        Some("gateway") => expand_gateway_preset(import, path),
        Some("media") => expand_media_preset(import, path),
        Some("xai") => expand_xai_preset(import, path),
        _ => Err(load_error(
            path,
            "unknown preset; expected cursor, devin, factory, fx, gateway, media, or xai",
        )),
    }
}

fn expand_cursor_preset(import: &ImportSpec, path: &Path) -> Result<Value, ConfigError> {
    let alias = import.alias.as_deref().unwrap_or("cursor");
    if alias.is_empty()
        || !alias
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(load_error(path, "invalid preset alias"));
    }
    for key in import.parameters.keys() {
        if !matches!(
            key.as_str(),
            "bind" | "reasoning_effort" | "model_prefix" | "upstream_url" | "secret"
        ) {
            return Err(unknown_preset_parameter(path, key));
        }
    }

    let mut preset: Value = serde_yml::from_str(include_str!("../../../presets/cursor.yaml"))
        .map_err(|error| load_error(path, &format!("invalid built-in cursor preset: {error}")))?;
    rename_named_key(&mut preset, "listeners", "listener", alias, path)?;
    rename_named_key(&mut preset, "upstreams", "upstream", alias, path)?;
    let route_id = format!("{alias}-route");
    let route = first_route_mut(&mut preset, path)?;
    route.insert(Value::String("id".to_owned()), Value::String(route_id));
    route.insert(
        Value::String("listen".to_owned()),
        Value::String(alias.to_owned()),
    );
    let target = route
        .get_mut(Value::String("target".to_owned()))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| load_error(path, "cursor preset target is invalid"))?;
    target.insert(
        Value::String("provider".to_owned()),
        Value::String(alias.to_owned()),
    );

    if let Some(value) = import.parameters.get("bind") {
        set_named_field(
            &mut preset,
            "listeners",
            alias,
            "bind",
            string_value(value, path, "cursor")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("upstream_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            alias,
            "url",
            string_value(value, path, "cursor")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("secret") {
        let upstream = named_declaration_mut(&mut preset, "upstreams", alias, path)?;
        let auth = upstream
            .get_mut(Value::String("auth".to_owned()))
            .and_then(Value::as_mapping_mut)
            .ok_or_else(|| load_error(path, "cursor preset auth is invalid"))?;
        auth.insert(
            Value::String("secret".to_owned()),
            Value::String(string_value(value, path, "cursor")?),
        );
    }
    if let Some(value) = import.parameters.get("reasoning_effort") {
        set_cursor_transform_parameter(
            &mut preset,
            "value",
            string_value(value, path, "cursor")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("model_prefix") {
        set_cursor_transform_parameter(
            &mut preset,
            "prefix",
            string_value(value, path, "cursor")?,
            path,
        )?;
    }
    Ok(preset)
}

fn expand_factory_preset(import: &ImportSpec, path: &Path) -> Result<Value, ConfigError> {
    for key in import.parameters.keys() {
        if !matches!(key.as_str(), "bind" | "upstream_url" | "secret") {
            return Err(unknown_preset_parameter(path, key));
        }
    }
    let alias = import.alias.as_deref().unwrap_or("factory");
    if alias.is_empty()
        || !alias
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(load_error(path, "invalid preset alias"));
    }
    let mut preset: Value = serde_yml::from_str(include_str!("../../../presets/factory.yaml"))
        .map_err(|error| load_error(path, &format!("invalid built-in factory preset: {error}")))?;
    rename_named_key(&mut preset, "listeners", "factory", alias, path)?;
    rename_named_key(&mut preset, "upstreams", "factory", alias, path)?;
    rewrite_factory_routes(&mut preset, alias, path)?;

    if let Some(value) = import.parameters.get("bind") {
        set_named_field(
            &mut preset,
            "listeners",
            alias,
            "bind",
            string_value(value, path, "factory")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("upstream_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            alias,
            "url",
            string_value(value, path, "factory")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("secret") {
        let upstream = named_declaration_mut(&mut preset, "upstreams", alias, path)?;
        let auth = upstream
            .entry(Value::String("auth".to_owned()))
            .or_insert_with(|| Value::Mapping(Mapping::new()))
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "factory preset auth is invalid"))?;
        auth.insert(
            Value::String("secret".to_owned()),
            Value::String(string_value(value, path, "factory")?),
        );
    }
    Ok(preset)
}

fn rewrite_factory_routes(root: &mut Value, alias: &str, path: &Path) -> Result<(), ConfigError> {
    let routes = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| load_error(path, "factory preset routes are invalid"))?;
    for route in routes {
        let route = route
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "factory preset route is invalid"))?;
        let route_id = route
            .get(Value::String("id".to_owned()))
            .and_then(Value::as_str)
            .ok_or_else(|| load_error(path, "factory preset route ID is missing"))?;
        route.insert(
            Value::String("id".to_owned()),
            Value::String(format!("{alias}-{route_id}")),
        );
        route.insert(
            Value::String("listen".to_owned()),
            Value::String(alias.to_owned()),
        );
        if let Some(Value::Mapping(target)) = route.get_mut(Value::String("target".to_owned())) {
            if target
                .get(Value::String("provider".to_owned()))
                .and_then(Value::as_str)
                == Some("factory")
            {
                target.insert(
                    Value::String("provider".to_owned()),
                    Value::String(alias.to_owned()),
                );
            }
        }
    }
    Ok(())
}

fn expand_fx_preset(import: &ImportSpec, path: &Path) -> Result<Value, ConfigError> {
    for key in import.parameters.keys() {
        if !matches!(key.as_str(), "bind" | "upstream_url" | "secret") {
            return Err(unknown_preset_parameter(path, key));
        }
    }
    let alias = import.alias.as_deref().unwrap_or("fx");
    if alias.is_empty()
        || !alias
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(load_error(path, "invalid preset alias"));
    }
    let mut preset: Value = serde_yml::from_str(include_str!("../../../presets/fx.yaml"))
        .map_err(|error| load_error(path, &format!("invalid built-in fx preset: {error}")))?;
    rename_named_key(&mut preset, "listeners", "fx", alias, path)?;
    rename_named_key(&mut preset, "upstreams", "fx", alias, path)?;
    rewrite_fx_routes(&mut preset, alias, path)?;

    if let Some(value) = import.parameters.get("bind") {
        set_named_field(
            &mut preset,
            "listeners",
            alias,
            "bind",
            string_value(value, path, "fx")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("upstream_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            alias,
            "url",
            string_value(value, path, "fx")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("secret") {
        let upstream = named_declaration_mut(&mut preset, "upstreams", alias, path)?;
        let auth = upstream
            .entry(Value::String("auth".to_owned()))
            .or_insert_with(|| Value::Mapping(Mapping::new()))
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "fx preset auth is invalid"))?;
        auth.insert(
            Value::String("secret".to_owned()),
            Value::String(string_value(value, path, "fx")?),
        );
    }
    Ok(preset)
}

fn rewrite_fx_routes(root: &mut Value, alias: &str, path: &Path) -> Result<(), ConfigError> {
    let routes = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| load_error(path, "fx preset routes are invalid"))?;
    for route in routes {
        let route = route
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "fx preset route is invalid"))?;
        let route_id = route
            .get(Value::String("id".to_owned()))
            .and_then(Value::as_str)
            .ok_or_else(|| load_error(path, "fx preset route ID is missing"))?;
        route.insert(
            Value::String("id".to_owned()),
            Value::String(format!("{alias}-{route_id}")),
        );
        route.insert(
            Value::String("listen".to_owned()),
            Value::String(alias.to_owned()),
        );
        if let Some(Value::Mapping(target)) = route.get_mut(Value::String("target".to_owned())) {
            if target
                .get(Value::String("provider".to_owned()))
                .and_then(Value::as_str)
                == Some("fx")
            {
                target.insert(
                    Value::String("provider".to_owned()),
                    Value::String(alias.to_owned()),
                );
            }
        }
    }
    Ok(())
}

/// Expand the universal turnkey gateway preset.
///
/// The preset declares one REST upstream and one WebSocket upstream because a
/// WebSocket route requires a `ws`/`wss` transport, exactly like the xAI
/// preset. Every route it carries is renamed under the alias so several
/// gateways can coexist on one deployment.
/// How one gateway route decides whether a provider can serve it.
enum GatewaySurface {
    /// The provider must speak this request dialect on the wire.
    Dialect(&'static str),
    /// The provider's documented model-discovery path must match, which is how
    /// an OpenAI-shaped `/v1/models` list is told apart from Gemini's
    /// `/v1beta/models` without guessing from the dialect.
    Discovery(&'static str),
}

/// Each gateway route's surface and the provider endpoint family it speaks.
///
/// A route is mounted only when the selected provider documents that family
/// and satisfies the surface, so a Gemini path is never mounted against an
/// Anthropic upstream merely because both document `models`.
const GATEWAY_ROUTE_SURFACE: [(&str, GatewaySurface, &str); 19] = [
    ("models", GatewaySurface::Discovery("/v1/models"), "models"),
    (
        "chat-completions",
        GatewaySurface::Dialect("openai"),
        "chat_completions",
    ),
    ("responses", GatewaySurface::Dialect("openai"), "responses"),
    (
        "responses-compact",
        GatewaySurface::Dialect("openai"),
        "responses",
    ),
    (
        "responses-websocket",
        GatewaySurface::Dialect("openai"),
        "responses",
    ),
    ("messages", GatewaySurface::Dialect("anthropic"), "messages"),
    (
        "messages-count-tokens",
        GatewaySurface::Dialect("anthropic"),
        "messages",
    ),
    (
        "gemini-models",
        GatewaySurface::Discovery("/v1beta/models"),
        "models",
    ),
    (
        "gemini-model-get",
        GatewaySurface::Discovery("/v1beta/models"),
        "models",
    ),
    (
        "gemini-model-actions",
        GatewaySurface::Dialect("gemini"),
        "generate_content",
    ),
    (
        "gemini-interactions-v1-create",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
    (
        "gemini-interactions-v1-resources",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
    (
        "gemini-interactions-v1-cancel",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
    (
        "gemini-interactions-v1beta-create",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
    (
        "gemini-interactions-v1beta-resources",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
    (
        "gemini-interactions-v1beta-cancel",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
    (
        "gemini-interactions-v1beta2-create",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
    (
        "gemini-interactions-v1beta2-resources",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
    (
        "gemini-interactions-v1beta2-cancel",
        GatewaySurface::Dialect("gemini"),
        "interactions",
    ),
];

/// Remove every gateway route the selected provider does not document.
fn retain_supported_gateway_routes(
    root: &mut Value,
    provider_id: &str,
    path: &Path,
) -> Result<(), ConfigError> {
    let provider = ProviderCatalog::builtin().get(provider_id).ok_or_else(|| {
        load_error(
            path,
            &format!("gateway preset provider `{provider_id}` is not a provider Pooler ships an endpoint for"),
        )
    })?;
    let integration = &provider.integration;
    let routes = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| load_error(path, "gateway preset routes are invalid"))?;
    let mut failure = None;
    routes.retain(|route| {
        let Some(id) = route
            .as_mapping()
            .and_then(|route| route.get(Value::String("id".to_owned())))
            .and_then(Value::as_str)
        else {
            failure = Some("gateway preset route ID is missing");
            return true;
        };
        let Some((_, surface, family)) = GATEWAY_ROUTE_SURFACE
            .iter()
            .find(|(route_id, _, _)| *route_id == id)
        else {
            failure = Some("gateway preset route is not classified");
            return true;
        };
        let serves_surface = match surface {
            GatewaySurface::Dialect(dialect) => *dialect == integration.request_dialect,
            GatewaySurface::Discovery(discovery) => {
                integration.discovery_path.as_deref() == Some(*discovery)
            }
        };
        serves_surface
            && integration
                .endpoint_families
                .iter()
                .any(|documented| documented == family)
    });
    if let Some(message) = failure {
        return Err(load_error(path, message));
    }
    if routes.is_empty() {
        return Err(load_error(
            path,
            &format!(
                "gateway preset provider `{provider_id}` documents no mountable endpoint family"
            ),
        ));
    }
    Ok(())
}

fn configure_gateway_responses_codecs(
    root: &mut Value,
    provider_id: &str,
    path: &Path,
) -> Result<(), ConfigError> {
    let routes = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| load_error(path, "gateway preset routes are invalid"))?;
    let Some(route) = routes
        .iter_mut()
        .find(|route| {
            route
                .as_mapping()
                .and_then(|route| route.get(Value::String("id".to_owned())))
                .and_then(Value::as_str)
                == Some("responses")
        })
        .and_then(Value::as_mapping_mut)
    else {
        return Ok(());
    };
    if provider_id == "openai" {
        return Ok(());
    }
    if provider_id != "xai" {
        return Err(load_error(
            path,
            &format!(
                "gateway preset provider `{provider_id}` does not support Pooler's semantic Responses WebSocket transport"
            ),
        ));
    }

    for (section, decoder, encoder) in [
        ("ingress", "decode.xai.responses", "encode.xai.responses"),
        (
            "response",
            "decode.xai.responses.events",
            "encode.xai.responses.events",
        ),
    ] {
        let mapping = route
            .get_mut(Value::String(section.to_owned()))
            .and_then(Value::as_mapping_mut)
            .ok_or_else(|| load_error(path, "gateway Responses codecs are invalid"))?;
        mapping.insert(
            Value::String("decoder".to_owned()),
            Value::String(decoder.to_owned()),
        );
        mapping.insert(
            Value::String("encoder".to_owned()),
            Value::String(encoder.to_owned()),
        );
    }
    Ok(())
}

fn expand_gateway_preset(import: &ImportSpec, path: &Path) -> Result<Value, ConfigError> {
    for key in import.parameters.keys() {
        if !matches!(
            key.as_str(),
            "bind" | "provider" | "upstream_url" | "websocket_url" | "secret"
        ) {
            return Err(unknown_preset_parameter(path, key));
        }
    }
    let alias = import.alias.as_deref().unwrap_or("gateway");
    if alias.is_empty()
        || !alias
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(load_error(path, "invalid preset alias"));
    }
    let mut preset: Value = serde_yml::from_str(include_str!("../../../presets/gateway.yaml"))
        .map_err(|error| load_error(path, &format!("invalid built-in gateway preset: {error}")))?;
    let provider_id = import
        .parameters
        .get("provider")
        .map(|value| string_value(value, path, "gateway"))
        .transpose()?
        .unwrap_or_else(|| "openai".to_owned());
    retain_supported_gateway_routes(&mut preset, &provider_id, path)?;
    configure_gateway_responses_codecs(&mut preset, &provider_id, path)?;
    let websocket_alias = format!("{alias}-websocket");
    rename_named_key(&mut preset, "listeners", "gateway", alias, path)?;
    rename_named_key(
        &mut preset,
        "upstreams",
        "gateway-websocket",
        &websocket_alias,
        path,
    )?;
    rename_named_key(&mut preset, "upstreams", "gateway", alias, path)?;
    rewrite_gateway_routes(&mut preset, alias, &websocket_alias, path)?;

    if let Some(value) = import.parameters.get("bind") {
        set_named_field(
            &mut preset,
            "listeners",
            alias,
            "bind",
            string_value(value, path, "gateway")?,
            path,
        )?;
    }
    // Both upstreams carry the provider identity so the WebSocket route
    // authenticates with the same documented placement as the REST routes.
    if let Some(value) = import.parameters.get("provider") {
        let provider = string_value(value, path, "gateway")?;
        for upstream_id in [alias, websocket_alias.as_str()] {
            set_named_field(
                &mut preset,
                "upstreams",
                upstream_id,
                "known_provider",
                provider.clone(),
                path,
            )?;
        }
    }
    // An explicit URL outranks the shipped provider base URL, which is what a
    // private deployment or a loopback test needs.
    if let Some(value) = import.parameters.get("upstream_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            alias,
            "url",
            string_value(value, path, "gateway")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("websocket_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            &websocket_alias,
            "url",
            string_value(value, path, "gateway")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("secret") {
        let secret = string_value(value, path, "gateway")?;
        for upstream_id in [alias, websocket_alias.as_str()] {
            let upstream = named_declaration_mut(&mut preset, "upstreams", upstream_id, path)?;
            let auth = upstream
                .get_mut(Value::String("auth".to_owned()))
                .and_then(Value::as_mapping_mut)
                .ok_or_else(|| load_error(path, "gateway preset auth is invalid"))?;
            auth.insert(
                Value::String("secret".to_owned()),
                Value::String(secret.clone()),
            );
        }
    }
    Ok(preset)
}

fn rewrite_gateway_routes(
    root: &mut Value,
    alias: &str,
    websocket_alias: &str,
    path: &Path,
) -> Result<(), ConfigError> {
    let routes = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| load_error(path, "gateway preset routes are invalid"))?;
    for route in routes {
        let route = route
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "gateway preset route is invalid"))?;
        let route_id = route
            .get(Value::String("id".to_owned()))
            .and_then(Value::as_str)
            .ok_or_else(|| load_error(path, "gateway preset route ID is missing"))?;
        route.insert(
            Value::String("id".to_owned()),
            Value::String(format!("{alias}-{route_id}")),
        );
        route.insert(
            Value::String("listen".to_owned()),
            Value::String(alias.to_owned()),
        );
        let target = route
            .get_mut(Value::String("target".to_owned()))
            .and_then(Value::as_mapping_mut)
            .ok_or_else(|| load_error(path, "gateway preset target is invalid"))?;
        let provider = target
            .get(Value::String("provider".to_owned()))
            .and_then(Value::as_str)
            .ok_or_else(|| load_error(path, "gateway preset target provider is missing"))?;
        let provider = match provider {
            "gateway" => alias,
            "gateway-websocket" => websocket_alias,
            _ => {
                return Err(load_error(
                    path,
                    "gateway preset target provider is invalid",
                ))
            }
        };
        target.insert(
            Value::String("provider".to_owned()),
            Value::String(provider.to_owned()),
        );
    }
    Ok(())
}

fn expand_media_preset(import: &ImportSpec, path: &Path) -> Result<Value, ConfigError> {
    for key in import.parameters.keys() {
        if !matches!(key.as_str(), "bind" | "upstream_url" | "secret") {
            return Err(unknown_preset_parameter(path, key));
        }
    }
    let alias = import.alias.as_deref().unwrap_or("media");
    if alias.is_empty()
        || !alias
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(load_error(path, "invalid preset alias"));
    }
    let mut preset: Value = serde_yml::from_str(include_str!("../../../presets/media.yaml"))
        .map_err(|error| load_error(path, &format!("invalid built-in media preset: {error}")))?;
    rename_named_key(&mut preset, "listeners", "media", alias, path)?;
    rename_named_key(&mut preset, "upstreams", "media", alias, path)?;
    rewrite_media_routes(&mut preset, alias, path)?;

    if let Some(value) = import.parameters.get("bind") {
        set_named_field(
            &mut preset,
            "listeners",
            alias,
            "bind",
            string_value(value, path, "media")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("upstream_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            alias,
            "url",
            string_value(value, path, "media")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("secret") {
        let upstream = named_declaration_mut(&mut preset, "upstreams", alias, path)?;
        let auth = upstream
            .entry(Value::String("auth".to_owned()))
            .or_insert_with(|| Value::Mapping(Mapping::new()))
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "media preset auth is invalid"))?;
        auth.insert(
            Value::String("secret".to_owned()),
            Value::String(string_value(value, path, "media")?),
        );
    }
    Ok(preset)
}

fn rewrite_media_routes(root: &mut Value, alias: &str, path: &Path) -> Result<(), ConfigError> {
    let routes = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| load_error(path, "media preset routes are invalid"))?;
    for route in routes {
        let route = route
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "media preset route is invalid"))?;
        let route_id = route
            .get(Value::String("id".to_owned()))
            .and_then(Value::as_str)
            .ok_or_else(|| load_error(path, "media preset route ID is missing"))?;
        route.insert(
            Value::String("id".to_owned()),
            Value::String(format!("{alias}-{route_id}")),
        );
        route.insert(
            Value::String("listen".to_owned()),
            Value::String(alias.to_owned()),
        );
        let target = route
            .get_mut(Value::String("target".to_owned()))
            .and_then(Value::as_mapping_mut)
            .ok_or_else(|| load_error(path, "media preset target is invalid"))?;
        if target
            .get(Value::String("provider".to_owned()))
            .and_then(Value::as_str)
            != Some("media")
        {
            return Err(load_error(path, "media preset target provider is invalid"));
        }
        target.insert(
            Value::String("provider".to_owned()),
            Value::String(alias.to_owned()),
        );
    }
    Ok(())
}

fn expand_xai_preset(import: &ImportSpec, path: &Path) -> Result<Value, ConfigError> {
    for key in import.parameters.keys() {
        if !matches!(
            key.as_str(),
            "bind" | "rest_url" | "websocket_url" | "secret"
        ) {
            return Err(unknown_preset_parameter(path, key));
        }
    }
    let alias = import.alias.as_deref().unwrap_or("xai");
    if alias.is_empty()
        || !alias
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(load_error(path, "invalid preset alias"));
    }
    let mut preset: Value = serde_yml::from_str(include_str!("../../../presets/xai.yaml"))
        .map_err(|error| load_error(path, &format!("invalid built-in xai preset: {error}")))?;
    let rest_alias = format!("{alias}-rest");
    let websocket_alias = format!("{alias}-websocket");
    rename_named_key(&mut preset, "listeners", "xai", alias, path)?;
    rename_named_key(&mut preset, "upstreams", "xai-rest", &rest_alias, path)?;
    rename_named_key(
        &mut preset,
        "upstreams",
        "xai-websocket",
        &websocket_alias,
        path,
    )?;
    rewrite_xai_routes(&mut preset, alias, &rest_alias, &websocket_alias, path)?;

    if let Some(value) = import.parameters.get("bind") {
        set_named_field(
            &mut preset,
            "listeners",
            alias,
            "bind",
            string_value(value, path, "xai")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("rest_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            &rest_alias,
            "url",
            string_value(value, path, "xai")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("websocket_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            &websocket_alias,
            "url",
            string_value(value, path, "xai")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("secret") {
        let secret = string_value(value, path, "xai")?;
        for upstream_id in [&rest_alias, &websocket_alias] {
            let upstream = named_declaration_mut(&mut preset, "upstreams", upstream_id, path)?;
            let auth = upstream
                .get_mut(Value::String("auth".to_owned()))
                .and_then(Value::as_mapping_mut)
                .ok_or_else(|| load_error(path, "xai preset auth is invalid"))?;
            auth.insert(
                Value::String("secret".to_owned()),
                Value::String(secret.clone()),
            );
        }
    }
    Ok(preset)
}

fn rewrite_xai_routes(
    root: &mut Value,
    alias: &str,
    rest_alias: &str,
    websocket_alias: &str,
    path: &Path,
) -> Result<(), ConfigError> {
    let routes = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| load_error(path, "xai preset routes are invalid"))?;
    for route in routes {
        let route = route
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "xai preset route is invalid"))?;
        let route_id = route
            .get(Value::String("id".to_owned()))
            .and_then(Value::as_str)
            .ok_or_else(|| load_error(path, "xai preset route ID is missing"))?;
        route.insert(
            Value::String("id".to_owned()),
            Value::String(format!("{alias}-{route_id}")),
        );
        route.insert(
            Value::String("listen".to_owned()),
            Value::String(alias.to_owned()),
        );
        let target = route
            .get_mut(Value::String("target".to_owned()))
            .and_then(Value::as_mapping_mut)
            .ok_or_else(|| load_error(path, "xai preset target is invalid"))?;
        let provider = target
            .get(Value::String("provider".to_owned()))
            .and_then(Value::as_str)
            .ok_or_else(|| load_error(path, "xai preset target provider is missing"))?;
        let provider = match provider {
            "xai-rest" => rest_alias,
            "xai-websocket" => websocket_alias,
            _ => return Err(load_error(path, "xai preset target provider is invalid")),
        };
        target.insert(
            Value::String("provider".to_owned()),
            Value::String(provider.to_owned()),
        );
    }
    Ok(())
}

fn expand_devin_preset(import: &ImportSpec, path: &Path) -> Result<Value, ConfigError> {
    for key in import.parameters.keys() {
        if !matches!(key.as_str(), "bind" | "upstream_url" | "secret") {
            return Err(unknown_preset_parameter(path, key));
        }
    }

    let mut preset: Value = serde_yml::from_str(include_str!("../../../presets/devin.yaml"))
        .map_err(|error| load_error(path, &format!("invalid built-in devin preset: {error}")))?;
    let alias = import.alias.as_deref().unwrap_or("devin");
    if alias.is_empty()
        || !alias
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(load_error(path, "invalid preset alias"));
    }
    rename_named_key(&mut preset, "listeners", "listener", alias, path)?;
    rename_named_key(&mut preset, "upstreams", "upstream", alias, path)?;
    rewrite_devin_routes(&mut preset, alias, path)?;
    let route = first_route_mut(&mut preset, path)?;
    route.insert(
        Value::String("id".to_owned()),
        Value::String(format!("{alias}-route")),
    );
    route.insert(
        Value::String("listen".to_owned()),
        Value::String(alias.to_owned()),
    );
    let target = route
        .get_mut(Value::String("target".to_owned()))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| load_error(path, "devin preset target is invalid"))?;
    target.insert(
        Value::String("provider".to_owned()),
        Value::String(alias.to_owned()),
    );

    if let Some(value) = import.parameters.get("bind") {
        set_named_field(
            &mut preset,
            "listeners",
            alias,
            "bind",
            string_value(value, path, "devin")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("upstream_url") {
        set_named_field(
            &mut preset,
            "upstreams",
            alias,
            "url",
            string_value(value, path, "devin")?,
            path,
        )?;
    }
    if let Some(value) = import.parameters.get("secret") {
        let upstream = named_declaration_mut(&mut preset, "upstreams", alias, path)?;
        let auth = upstream
            .get_mut(Value::String("auth".to_owned()))
            .and_then(Value::as_mapping_mut)
            .ok_or_else(|| load_error(path, "devin preset auth is invalid"))?;
        auth.insert(
            Value::String("secret".to_owned()),
            Value::String(string_value(value, path, "devin")?),
        );
    }
    Ok(preset)
}

fn unknown_preset_parameter(path: &Path, key: &str) -> ConfigError {
    load_error(path, &format!("unknown preset parameter `{key}`"))
}

fn rewrite_devin_routes(root: &mut Value, alias: &str, path: &Path) -> Result<(), ConfigError> {
    let routes = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| load_error(path, "devin preset routes are invalid"))?;
    for (index, route) in routes.iter_mut().enumerate() {
        let route = route
            .as_mapping_mut()
            .ok_or_else(|| load_error(path, "devin preset route is invalid"))?;
        let route_id = route
            .get(Value::String("id".to_owned()))
            .and_then(Value::as_str)
            .ok_or_else(|| load_error(path, "devin preset route ID is missing"))?;
        route.insert(
            Value::String("id".to_owned()),
            Value::String(if index == 0 {
                format!("{alias}-route")
            } else {
                format!("{alias}-{route_id}")
            }),
        );
        route.insert(
            Value::String("listen".to_owned()),
            Value::String(alias.to_owned()),
        );
        if let Some(target) = route.get_mut(Value::String("target".to_owned())) {
            match target {
                Value::String(name) if name == "upstream" => *name = alias.to_owned(),
                Value::Mapping(target) => {
                    if target
                        .get(Value::String("provider".to_owned()))
                        .and_then(Value::as_str)
                        == Some("upstream")
                    {
                        target.insert(
                            Value::String("provider".to_owned()),
                            Value::String(alias.to_owned()),
                        );
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn rename_named_key(
    root: &mut Value,
    section: &str,
    old: &str,
    new: &str,
    path: &Path,
) -> Result<(), ConfigError> {
    let section = root
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String(section.to_owned())))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| load_error(path, "preset section is invalid"))?;
    let value = section
        .remove(Value::String(old.to_owned()))
        .ok_or_else(|| load_error(path, "preset declaration is missing"))?;
    section.insert(Value::String(new.to_owned()), value);
    Ok(())
}

fn named_declaration_mut<'a>(
    root: &'a mut Value,
    section: &str,
    id: &str,
    path: &Path,
) -> Result<&'a mut Mapping, ConfigError> {
    root.as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String(section.to_owned())))
        .and_then(Value::as_mapping_mut)
        .and_then(|mapping| mapping.get_mut(Value::String(id.to_owned())))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| load_error(path, "preset declaration is invalid"))
}

fn set_named_field(
    root: &mut Value,
    section: &str,
    id: &str,
    field: &str,
    value: String,
    path: &Path,
) -> Result<(), ConfigError> {
    named_declaration_mut(root, section, id, path)?
        .insert(Value::String(field.to_owned()), Value::String(value));
    Ok(())
}

fn first_route_mut<'a>(root: &'a mut Value, path: &Path) -> Result<&'a mut Mapping, ConfigError> {
    root.as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(Value::String("routes".to_owned())))
        .and_then(Value::as_sequence_mut)
        .and_then(|routes| routes.first_mut())
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| load_error(path, "preset route is invalid"))
}

fn set_cursor_transform_parameter(
    root: &mut Value,
    field: &str,
    value: String,
    path: &Path,
) -> Result<(), ConfigError> {
    let route = first_route_mut(root, path)?;
    let parameters = route
        .get_mut(Value::String("request".to_owned()))
        .and_then(Value::as_mapping_mut)
        .and_then(|request| request.get_mut(Value::String("steps".to_owned())))
        .and_then(Value::as_sequence_mut)
        .and_then(|steps| steps.first_mut())
        .and_then(Value::as_mapping_mut)
        .and_then(|step| step.get_mut(Value::String("with".to_owned())))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| load_error(path, "cursor preset transform is invalid"))?;
    parameters.insert(Value::String(field.to_owned()), Value::String(value));
    Ok(())
}

fn string_value(value: &Value, path: &Path, preset: &str) -> Result<String, ConfigError> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| load_error(path, &format!("{preset} preset parameters must be strings")))
}

fn normalize_provider_alias(document: &mut Value, path: &Path) -> Result<(), ConfigError> {
    let Some(mapping) = document.as_mapping_mut() else {
        return Err(load_error(path, "configuration root must be a mapping"));
    };
    let providers = Value::String("providers".to_owned());
    let upstreams = Value::String("upstreams".to_owned());
    if mapping.contains_key(&providers) && mapping.contains_key(&upstreams) {
        return Err(load_error(path, "use only one of providers or upstreams"));
    }
    if let Some(value) = mapping.remove(&providers) {
        mapping.insert(upstreams, value);
    }
    Ok(())
}

fn collect_origins(document: &Value, path: &Path) -> BTreeMap<String, Arc<str>> {
    let mut origins = BTreeMap::new();
    let Some(root) = document.as_mapping() else {
        return origins;
    };
    let source: Arc<str> = Arc::from(path.display().to_string());
    if root.contains_key(Value::String("management".to_owned())) {
        origins.insert("management".to_owned(), Arc::clone(&source));
    }
    if root.contains_key(Value::String("catalog".to_owned())) {
        origins.insert("catalog".to_owned(), Arc::clone(&source));
    }
    for section in [
        "listeners",
        "upstreams",
        "accounts",
        "credentials",
        "account_pools",
        "pools",
        "policies",
    ] {
        if let Some(mapping) = root
            .get(Value::String(section.to_owned()))
            .and_then(Value::as_mapping)
        {
            for id in mapping.keys().filter_map(Value::as_str) {
                origins.insert(format!("{section}.{id}"), Arc::clone(&source));
            }
        }
    }
    for section in ["routes", "models"] {
        if let Some(sequence) = root
            .get(Value::String(section.to_owned()))
            .and_then(Value::as_sequence)
        {
            for item in sequence {
                if let Ok(id) = declaration_id(item, path) {
                    origins.insert(format!("{section}.{id}"), Arc::clone(&source));
                }
            }
        }
    }
    origins
}

fn merge_resolved(
    base: &mut ResolvedDocument,
    incoming: ResolvedDocument,
    path: &Path,
    additive_sequences: bool,
) -> Result<(), ConfigError> {
    base.dependencies.extend(incoming.dependencies);
    apply_origin_changes(
        &mut base.origins,
        &incoming.value,
        &incoming.origins,
        path,
        additive_sequences,
    );
    merge_document(&mut base.value, incoming.value, path, additive_sequences)
}

fn apply_origin_changes(
    base: &mut BTreeMap<String, Arc<str>>,
    incoming: &Value,
    incoming_origins: &BTreeMap<String, Arc<str>>,
    path: &Path,
    additive_sequences: bool,
) {
    let Some(root) = incoming.as_mapping() else {
        return;
    };
    if root.contains_key(Value::String("management".to_owned())) {
        if let Some(origin) = incoming_origins.get("management") {
            base.insert("management".to_owned(), Arc::clone(origin));
        }
    }
    if root.contains_key(Value::String("catalog".to_owned())) {
        if let Some(origin) = incoming_origins.get("catalog") {
            base.insert("catalog".to_owned(), Arc::clone(origin));
        }
    }
    for section in [
        "listeners",
        "upstreams",
        "accounts",
        "credentials",
        "account_pools",
        "pools",
        "policies",
    ] {
        if let Some(mapping) = root
            .get(Value::String(section.to_owned()))
            .and_then(Value::as_mapping)
        {
            for (id, declaration) in mapping {
                let Some(id) = id.as_str() else { continue };
                let key = format!("{section}.{id}");
                if directive_is_true(declaration, "remove") {
                    base.remove(&key);
                } else if let Some(origin) = incoming_origins.get(&key) {
                    base.insert(key, Arc::clone(origin));
                }
            }
        }
    }
    for section in ["routes", "models"] {
        let Some(sequence) = root
            .get(Value::String(section.to_owned()))
            .and_then(Value::as_sequence)
        else {
            continue;
        };
        if !additive_sequences && !sequence.iter().any(has_directive) {
            let prefix = format!("{section}.");
            base.retain(|key, _| !key.starts_with(&prefix));
        }
        for declaration in sequence {
            let Ok(id) = declaration_id(declaration, path) else {
                continue;
            };
            let key = format!("{section}.{id}");
            if directive_is_true(declaration, "remove") {
                base.remove(&key);
            } else if let Some(origin) = incoming_origins.get(&key) {
                base.insert(key, Arc::clone(origin));
            }
        }
    }
}

fn directive_is_true(value: &Value, key: &str) -> bool {
    value
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String(key.to_owned())))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn merge_document(
    base: &mut Value,
    incoming: Value,
    path: &Path,
    additive_sequences: bool,
) -> Result<(), ConfigError> {
    let incoming = incoming
        .as_mapping()
        .ok_or_else(|| load_error(path, "configuration root must be a mapping"))?;
    let base = base
        .as_mapping_mut()
        .ok_or_else(|| load_error(path, "configuration root must be a mapping"))?;
    for (key, value) in incoming {
        let name = key.as_str().unwrap_or_default();
        match name {
            "listeners" | "upstreams" | "accounts" | "credentials" | "account_pools" | "pools"
            | "policies" => merge_named_map(base, key, value, path)?,
            "routes" | "models" => {
                merge_named_sequence(base, key, value, path, additive_sequences)?;
            }
            _ => merge_entry(base, key.clone(), value.clone(), path)?,
        }
    }
    Ok(())
}

fn merge_named_map(
    base: &mut Mapping,
    key: &Value,
    incoming: &Value,
    path: &Path,
) -> Result<(), ConfigError> {
    let incoming = incoming
        .as_mapping()
        .ok_or_else(|| load_error(path, "named declaration collection must be a mapping"))?;
    let target = base
        .entry(key.clone())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .ok_or_else(|| load_error(path, "cannot change named declaration collection type"))?;
    for (id, declaration) in incoming {
        let (mut value, merge, remove) = strip_directives(declaration, path)?;
        if remove
            && value
                .as_mapping()
                .is_some_and(|mapping| !mapping.is_empty())
        {
            return Err(load_error(
                path,
                "remove declaration cannot contain other fields",
            ));
        }
        match (target.get_mut(id), merge, remove) {
            (_, _, true) => {
                if target.remove(id).is_none() {
                    return Err(load_error(path, "cannot remove a missing declaration"));
                }
            }
            (Some(existing), true, false) => merge_value(existing, &mut value, path)?,
            (Some(_), false, false) => {
                return Err(load_error(
                    path,
                    "duplicate declaration requires merge: true",
                ));
            }
            (None, true, false) => {
                return Err(load_error(path, "cannot merge a missing declaration"));
            }
            (None, false, false) => {
                target.insert(id.clone(), value);
            }
        }
    }
    Ok(())
}

fn merge_named_sequence(
    base: &mut Mapping,
    key: &Value,
    incoming: &Value,
    path: &Path,
    additive: bool,
) -> Result<(), ConfigError> {
    let incoming = incoming
        .as_sequence()
        .ok_or_else(|| load_error(path, "named declaration collection must be a list"))?;
    let per_id = additive || incoming.iter().any(has_directive);
    if !per_id {
        if base.get(key).is_some_and(|value| !value.is_sequence()) {
            return Err(load_error(path, "overlay cannot change a value's type"));
        }
        base.insert(key.clone(), incoming.clone().into());
        return Ok(());
    }
    let target = base
        .entry(key.clone())
        .or_insert_with(|| Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| load_error(path, "cannot change named declaration collection type"))?;
    for declaration in incoming {
        let (mut value, merge, remove) = strip_directives(declaration, path)?;
        let id = declaration_id(&value, path)?;
        if remove && value.as_mapping().is_some_and(|mapping| mapping.len() != 1) {
            return Err(load_error(
                path,
                "remove declaration cannot contain fields other than id",
            ));
        }
        let existing = target
            .iter()
            .position(|item| declaration_id(item, path).ok() == Some(id));
        match (existing, merge, remove) {
            (Some(index), _, true) => {
                target.remove(index);
            }
            (None, _, true) => return Err(load_error(path, "cannot remove a missing declaration")),
            (Some(index), true, false) => merge_value(&mut target[index], &mut value, path)?,
            (Some(_), false, false) => {
                return Err(load_error(
                    path,
                    "duplicate declaration requires merge: true",
                ));
            }
            (None, true, false) => {
                return Err(load_error(path, "cannot merge a missing declaration"));
            }
            (None, false, false) => target.push(value),
        }
    }
    Ok(())
}

fn merge_entry(
    base: &mut Mapping,
    key: Value,
    incoming: Value,
    path: &Path,
) -> Result<(), ConfigError> {
    if let Some(existing) = base.get_mut(&key) {
        let mut incoming = incoming;
        merge_value(existing, &mut incoming, path)
    } else {
        base.insert(key, incoming);
        Ok(())
    }
}

fn merge_value(base: &mut Value, incoming: &mut Value, path: &Path) -> Result<(), ConfigError> {
    match (&mut *base, &mut *incoming) {
        (Value::Mapping(base), Value::Mapping(incoming)) => {
            for (key, value) in incoming.clone() {
                merge_entry(base, key, value, path)?;
            }
            Ok(())
        }
        (Value::Sequence(base), Value::Sequence(incoming)) => {
            *base = std::mem::take(incoming);
            Ok(())
        }
        (
            base @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)),
            incoming @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)),
        ) => {
            if std::mem::discriminant(base) != std::mem::discriminant(incoming) {
                return Err(load_error(path, "overlay cannot change a value's type"));
            }
            *base = std::mem::take(incoming);
            Ok(())
        }
        _ => Err(load_error(path, "overlay cannot change a value's type")),
    }
}

fn strip_directives(value: &Value, path: &Path) -> Result<(Value, bool, bool), ConfigError> {
    let mut value = value.clone();
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| load_error(path, "named declaration must be a mapping"))?;
    let merge = take_bool(mapping, "merge", path)?;
    let remove = take_bool(mapping, "remove", path)?;
    if merge && remove {
        return Err(load_error(path, "merge and remove cannot both be true"));
    }
    Ok((value, merge, remove))
}

fn take_bool(mapping: &mut Mapping, key: &str, path: &Path) -> Result<bool, ConfigError> {
    match mapping.remove(Value::String(key.to_owned())) {
        None => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(Value::Bool(false)) => {
            Err(load_error(path, &format!("{key} must be omitted or true")))
        }
        Some(_) => Err(load_error(path, &format!("{key} must be a boolean"))),
    }
}

fn has_directive(value: &Value) -> bool {
    value.as_mapping().is_some_and(|mapping| {
        mapping.contains_key(Value::String("merge".to_owned()))
            || mapping.contains_key(Value::String("remove".to_owned()))
    })
}

fn declaration_id<'a>(value: &'a Value, path: &Path) -> Result<&'a str, ConfigError> {
    value
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String("id".to_owned())))
        .and_then(Value::as_str)
        .ok_or_else(|| load_error(path, "named list declaration requires id"))
}

fn render_value(value: &Value, path: &Path) -> Result<String, ConfigError> {
    serde_yml::to_string(value).map_err(|error| load_error(path, &error.to_string()))
}

fn load_error(path: &Path, message: &str) -> ConfigError {
    ConfigError::Invalid {
        label: SourceLabel::start(&path.display().to_string()),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "pooler-config-loader-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("test directory");
            Self(path)
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, text).expect("test config");
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn resolves_relative_file_and_overlay_imports() {
        let dir = TestDir::new();
        dir.write(
            "base.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\nupstreams: {one: {url: http://127.0.0.1:2}}\nroutes: [{id: old, listen: local, target: one}]\n",
        );
        dir.write(
            "overlay.yaml",
            "version: 1\nlisteners: {local: {merge: true, bind: 127.0.0.1:3}}\nroutes: [{id: old, remove: true}, {id: new, listen: local, target: one}]\n",
        );
        let root = dir.write(
            "root.yaml",
            "imports: [{file: base.yaml}, {overlay: overlay.yaml}]\nversion: 1\n",
        );
        let config = load_path(&root)
            .expect("resolved config")
            .compile()
            .expect("compiled");
        assert_eq!(config.listeners()["local"].bind(), "127.0.0.1:3");
        assert!(config.route("old").is_none());
        assert!(config.route("new").is_some());
        let rendered = render_path(&root).expect("rendered");
        assert!(!rendered.contains("imports:"));
        assert!(!rendered.contains("merge:"));
        assert!(!rendered.contains("remove:"));
    }

    #[test]
    fn rejects_cycles_duplicates_and_type_changes() {
        let dir = TestDir::new();
        let first = dir.write("first.yaml", "imports: [{file: second.yaml}]\nversion: 1\n");
        dir.write("second.yaml", "imports: [{file: first.yaml}]\nversion: 1\n");
        assert!(ConfigLoader::default().load(&first).is_err());

        let base = dir.write(
            "base.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\n",
        );
        let duplicate = dir.write(
            "duplicate.yaml",
            "imports: [{file: base.yaml}]\nversion: 1\nlisteners: {local: {bind: 127.0.0.1:2}}\n",
        );
        assert!(render_path(&duplicate).is_err());

        let overlay = dir.write("bad-overlay.yaml", "version: []\n");
        let root = dir.write(
            "bad-root.yaml",
            &format!(
                "imports: [{{file: {}}}, {{overlay: {}}}]\nversion: 1\n",
                base.file_name().unwrap().to_string_lossy(),
                overlay.file_name().unwrap().to_string_lossy()
            ),
        );
        assert!(render_path(root).is_err());
    }

    #[test]
    fn expands_cursor_preset_with_namespaced_ids_and_parameters() {
        let dir = TestDir::new();
        let root = dir.write(
            "cursor.yaml",
            r#"
imports:
  - preset: cursor
    as: cursor-low
    with:
      bind: 127.0.0.1:9331
      reasoning_effort: low
      model_prefix: gpt-5.
      upstream_url: http://127.0.0.1:9319
      secret: env:CURSOR_UPSTREAM_KEY
version: 1
"#,
        );
        let config = load_path(&root)
            .expect("cursor preset")
            .compile()
            .expect("compiled");
        assert_eq!(config.listeners()["cursor-low"].bind(), "127.0.0.1:9331");
        let route = config.route("cursor-low-route").expect("preset route");
        assert_eq!(route.listener(), "cursor-low");
        assert_eq!(route.target().upstream(), "cursor-low");
        assert_eq!(route.request_steps()[0].model_prefix(), Some("gpt-5."));
        assert_eq!(route.request_steps()[0].value(), "low");
        let rendered = render_path(root).expect("rendered preset");
        assert!(rendered.contains("env:CURSOR_UPSTREAM_KEY"));
        assert!(!rendered.contains("preset:"));
    }

    #[test]
    fn multiple_cursor_presets_coexist() {
        let dir = TestDir::new();
        let root = dir.write(
            "cursors.yaml",
            r#"
imports:
  - {preset: cursor, as: cursor-low, with: {reasoning_effort: low}}
  - {preset: cursor, as: cursor-high, with: {bind: "127.0.0.1:8334", reasoning_effort: high}}
version: 1
"#,
        );
        let config = load_path(&root)
            .expect("cursor presets")
            .compile()
            .expect("compiled");
        assert!(config.route("cursor-low-route").is_some());
        assert!(config.route("cursor-high-route").is_some());
        assert_eq!(config.listeners().len(), 2);
    }

    #[test]
    fn expands_devin_preset_with_connect_framing_and_parameters() {
        let dir = TestDir::new();
        let root = dir.write(
            "devin.yaml",
            r#"
imports:
  - preset: devin
    as: devin-local
    with:
      bind: 127.0.0.1:9443
      upstream_url: http://127.0.0.1:9419
      secret: env:DEVIN_UPSTREAM_KEY
version: 1
"#,
        );
        let config = load_path(&root)
            .expect("devin preset")
            .compile()
            .expect("compiled");
        assert_eq!(config.listeners()["devin-local"].bind(), "127.0.0.1:9443");
        let route = config.route("devin-local-route").expect("preset route");
        assert_eq!(route.listener(), "devin-local");
        assert_eq!(route.target().upstream(), "devin-local");
        assert_eq!(route.ingress().framing(), Some("decode.connect.envelope"));
        assert_eq!(route.ingress().decoder(), Some("decode.devin.chat"));
        assert_eq!(route.response().encoder(), Some("encode.devin.connect"));
        assert_eq!(
            config.upstreams()["devin-local"]
                .auth()
                .expect("preset auth")
                .secret()
                .redacted(),
            "env:DEVIN_UPSTREAM_KEY"
        );

        let rendered = render_path(root).expect("rendered preset");
        assert!(rendered.contains("decode.connect.envelope"));
        assert!(rendered.contains("decode.devin.chat"));
        assert!(rendered.contains("encode.devin.connect"));
        assert!(rendered.contains("env:DEVIN_UPSTREAM_KEY"));
        assert!(!rendered.contains("preset:"));
    }

    #[test]
    fn expands_factory_preset_with_v3_v4_and_discovery_routes() {
        let dir = TestDir::new();
        let root = dir.write(
            "factory.yaml",
            r#"
imports:
  - preset: factory
    as: factory-local
    with:
      bind: 127.0.0.1:9332
      upstream_url: http://127.0.0.1:9319
version: 1
"#,
        );
        let config = load_path(&root)
            .expect("factory preset")
            .compile()
            .expect("compiled");
        assert_eq!(config.listeners()["factory-local"].bind(), "127.0.0.1:9332");
        assert!(config.route("factory-local-language-model-v3").is_some());
        assert!(config.route("factory-local-language-model-v4").is_some());
        assert!(config.route("factory-local-config-v3").is_some());
        assert!(config.route("factory-local-config-v4").is_some());
        let rendered = render_path(root).expect("rendered preset");
        assert!(!rendered.contains("preset:"));
    }

    #[test]
    fn expands_fx_preset_with_chat_and_model_routes() {
        let dir = TestDir::new();
        let root = dir.write(
            "fx.yaml",
            r#"
imports:
  - preset: fx
    as: fx-local
    with:
      bind: 127.0.0.1:9333
      upstream_url: http://127.0.0.1:9319
      secret: env:FX_TEST_KEY
version: 1
"#,
        );
        let config = load_path(&root)
            .expect("fx preset")
            .compile()
            .expect("compiled");
        assert_eq!(config.listeners()["fx-local"].bind(), "127.0.0.1:9333");
        for route_id in [
            "fx-local-language-model-v3",
            "fx-local-language-model-v4",
            "fx-local-models-coding-agent",
            "fx-local-models-openai",
        ] {
            assert!(config.route(route_id).is_some(), "missing {route_id}");
        }
        let chat = config
            .route("fx-local-language-model-v3")
            .expect("fx chat route");
        assert_eq!(chat.ingress().decoder(), Some("decode.fx.language_model"));
        assert_eq!(chat.response().encoder(), Some("encode.fx.events"));
        let models = config
            .route("fx-local-models-coding-agent")
            .expect("fx models route");
        assert_eq!(models.ingress().decoder(), Some("decode.fx.models.request"));
        assert_eq!(models.response().encoder(), Some("encode.fx.models"));
        assert_eq!(chat.target().upstream(), "fx-local");
        assert_eq!(models.target().upstream(), "fx-local");
        assert_eq!(
            config.upstreams()["fx-local"]
                .auth()
                .expect("fx auth")
                .secret()
                .redacted(),
            "env:FX_TEST_KEY"
        );
        let rendered = render_path(root).expect("rendered fx preset");
        assert!(rendered.contains("decode.fx.language_model"));
        assert!(rendered.contains("encode.fx.events"));
        assert!(rendered.contains("decode.fx.models.request"));
        assert!(rendered.contains("encode.fx.models"));
        assert!(!rendered.contains("preset:"));
    }

    #[test]
    fn fx_parameter_type_errors_name_the_fx_preset() {
        let dir = TestDir::new();
        let root = dir.write(
            "fx-invalid.yaml",
            "imports: [{preset: fx, with: {bind: 9333}}]\nversion: 1\n",
        );
        let error = load_path(root).expect_err("numeric fx parameter");
        assert!(error
            .to_string()
            .contains("fx preset parameters must be strings"));
        assert!(!error.to_string().contains("cursor preset parameters"));
    }

    #[test]
    fn expands_xai_preset_with_semantic_rest_and_bounded_raw_websocket() {
        let dir = TestDir::new();
        let root = dir.write(
            "xai.yaml",
            r#"
imports:
  - preset: xai
    as: grok-local
    with:
      bind: 127.0.0.1:9334
      rest_url: http://127.0.0.1:9319
      websocket_url: ws://127.0.0.1:9320
      secret: env:XAI_TEST_KEY
version: 1
"#,
        );
        let config = load_path(&root)
            .expect("xai preset")
            .compile()
            .expect("compiled");
        assert_eq!(config.listeners()["grok-local"].bind(), "127.0.0.1:9334");

        let chat = config
            .route("grok-local-chat-completions")
            .expect("xai Chat route");
        assert_eq!(chat.ingress().decoder(), Some("decode.xai.chat"));
        assert_eq!(chat.response().decoder(), Some("decode.xai.chat.events"));
        assert_eq!(chat.response().encoder(), Some("encode.xai.chat.events"));
        assert_eq!(chat.target().upstream(), "grok-local-rest");

        let responses = config
            .route("grok-local-responses-rest")
            .expect("xai Responses REST route");
        assert_eq!(responses.ingress().decoder(), Some("decode.xai.responses"));
        assert_eq!(
            responses.response().decoder(),
            Some("decode.xai.responses.events")
        );
        assert_eq!(
            responses.response().encoder(),
            Some("encode.xai.responses.events")
        );

        let websocket = config
            .route("grok-local-responses-websocket")
            .expect("xai Responses WebSocket route");
        assert_eq!(websocket.matcher().websocket(), Some(true));
        assert!(!websocket.ingress().mode().is_semantic());
        assert!(!websocket.response().mode().is_semantic());
        assert_eq!(websocket.target().upstream(), "grok-local-websocket");
        assert_eq!(websocket.limits().max_frame_bytes, 8 * 1024 * 1024);
        assert_eq!(websocket.limits().max_queue_bytes, 8 * 1024 * 1024);
        assert_eq!(websocket.limits().max_queue_items, 64);
        assert_eq!(websocket.limits().request_timeout, None);

        for upstream_id in ["grok-local-rest", "grok-local-websocket"] {
            assert_eq!(
                config.upstreams()[upstream_id]
                    .auth()
                    .expect("xai auth")
                    .secret()
                    .redacted(),
                "env:XAI_TEST_KEY"
            );
        }
        let rendered = render_path(root).expect("rendered xai preset");
        assert!(rendered.contains("decode.xai.responses"));
        assert!(rendered.contains("websocket: true"));
        assert!(!rendered.contains("preset:"));
    }

    #[test]
    fn rejects_unknown_devin_preset_parameters() {
        let dir = TestDir::new();
        let root = dir.write(
            "devin-invalid.yaml",
            "imports: [{preset: devin, with: {model: custom}}]\nversion: 1\n",
        );
        let error = load_path(root).expect_err("unknown preset parameter");
        assert!(error
            .to_string()
            .contains("unknown preset parameter `model`"));
    }

    #[test]
    fn route_conflicts_retain_import_and_overlay_sources() {
        let dir = TestDir::new();
        dir.write(
            "base.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\nupstreams: {local: {url: http://127.0.0.1:2}}\nroutes: [{id: base, listen: local, match: {path: /same}, target: local}, {id: remove-me, listen: local, match: {path: /other}, target: local}]\n",
        );
        dir.write(
            "overlay.yaml",
            "version: 1\nroutes: [{id: remove-me, remove: true}, {id: overlay, listen: local, match: {path: /same}, target: local}]\n",
        );
        let root = dir.write(
            "root.yaml",
            "imports: [{file: base.yaml}, {overlay: overlay.yaml}]\nversion: 1\n",
        );
        let error = load_path(root)
            .expect("resolved config")
            .compile()
            .expect_err("conflicting routes");
        let rendered = error.to_string();
        assert!(rendered.contains("base.yaml"));
        assert!(rendered.contains("overlay.yaml"));
    }

    #[test]
    fn imported_schema_errors_report_the_imported_source_and_field() {
        let dir = TestDir::new();
        dir.write(
            "bad.yaml",
            "version: 1\nlisteners: {local: {bnd: 127.0.0.1:1}}\n",
        );
        let root = dir.write("root.yaml", "imports: [{file: bad.yaml}]\nversion: 1\n");
        let error = load_path(root).expect_err("unknown imported field");
        let rendered = error.to_string();
        assert!(rendered.contains("bad.yaml"));
        assert!(rendered.contains("bnd"));
    }

    #[test]
    fn imported_dotted_ids_retain_their_source() {
        let dir = TestDir::new();
        dir.write(
            "bad.yaml",
            "version: 1\nupstreams: {a.b: {url: http://127.0.0.1:2, bogus: true}}\n",
        );
        let root = dir.write("root.yaml", "imports: [{file: bad.yaml}]\nversion: 1\n");
        let error = load_path(root).expect_err("unknown field in dotted upstream id");
        let rendered = error.to_string();
        assert!(rendered.contains("bad.yaml"));
        assert!(rendered.contains("bogus"));
    }

    #[test]
    fn remove_declarations_reject_unvalidated_fields() {
        let map_key = Value::String("listeners".to_owned());
        let mut map_base: Mapping =
            serde_yml::from_str("{listeners: {local: {bind: '127.0.0.1:1'}}}").expect("base map");
        let map_overlay: Value =
            serde_yml::from_str("{local: {remove: true, bogus: true}}").expect("map overlay");
        assert!(merge_named_map(
            &mut map_base,
            &map_key,
            &map_overlay,
            Path::new("overlay.yaml"),
        )
        .is_err());

        let list_key = Value::String("routes".to_owned());
        let mut list_base: Mapping =
            serde_yml::from_str("{routes: [{id: route, listen: local, target: local}]}")
                .expect("base list");
        let list_overlay: Value =
            serde_yml::from_str("[{id: route, remove: true, bogus: true}]").expect("list overlay");
        assert!(merge_named_sequence(
            &mut list_base,
            &list_key,
            &list_overlay,
            Path::new("overlay.yaml"),
            false,
        )
        .is_err());
    }

    #[test]
    fn import_depth_counts_nested_imports_not_the_root() {
        let dir = TestDir::new();
        let leaf = dir.write("leaf.yaml", "version: 1\n");
        assert!(ConfigLoader::new(0).render(&leaf).is_ok());
        let root = dir.write("root.yaml", "imports: [{file: leaf.yaml}]\nversion: 1\n");
        assert!(ConfigLoader::new(0).render(&root).is_err());
        assert!(ConfigLoader::new(1).render(&root).is_ok());
    }

    #[test]
    fn named_list_directives_are_true_only_and_never_mask_type_changes() {
        let key = Value::String("routes".to_owned());
        let mut wrong_type = Mapping::new();
        wrong_type.insert(key.clone(), Value::String("not-a-list".to_owned()));
        assert!(merge_named_sequence(
            &mut wrong_type,
            &key,
            &Value::Sequence(Vec::new()),
            Path::new("test.yaml"),
            false,
        )
        .is_err());

        let mut base = Mapping::new();
        let declaration: Value =
            serde_yml::from_str("{id: route, merge: false}").expect("declaration");
        assert!(merge_named_sequence(
            &mut base,
            &key,
            &Value::Sequence(vec![declaration]),
            Path::new("test.yaml"),
            false,
        )
        .is_err());
    }
}
