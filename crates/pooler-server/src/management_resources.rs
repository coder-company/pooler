//! Structured, redacted control-plane resources.
//!
//! The management transport owns authentication and draft activation.  This
//! module owns the resource vocabulary and the read-only graph projection so
//! resource handlers cannot accidentally expose source secrets or create a
//! second live configuration path.

use std::collections::{BTreeMap, BTreeSet};

use http::Method;
use ring::digest::{digest, SHA256};
use serde_json::{json, Map, Value};

use adapter_providers::{AuthPlacement, OpenAiCompatibleAdapter, ProviderOperation};
use pooler_config::{CompiledConfig, ModelPlan, ModelTargetPlan};
use pooler_core::ModelId;
use pooler_http::PoolingCoordinator;
use pooler_model_catalog::ProviderCatalog;
use url::Url;

use crate::config_management::TypedConfigPatch;
use crate::{merged_model_catalog_value, CatalogRuntime, ConfigSnapshot};

/// Version of the machine-readable control-plane graph and endpoint catalog.
pub(crate) const CONTROL_PLANE_SCHEMA_VERSION: u8 = 2;

/// Sections accepted by resource-specific draft mutations.
const RESOURCE_SECTIONS: &[(&str, &str, bool)] = &[
    ("providers", "upstreams", false),
    ("accounts", "accounts", false),
    ("pools", "account_pools", false),
    ("policies", "policies", false),
    ("routes", "routes", true),
    ("models", "models", true),
    ("bindings", "models", true),
];

/// A bounded parser failure.  The management layer maps this to the stable
/// Task-3 error envelope and deliberately does not include parser detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceMutationError {
    Invalid,
    Conflict,
    Unsupported,
    SecretReferenceRequired,
}

/// Return whether a path belongs to the structured control-plane namespace.
pub(crate) fn is_control_plane_path(path: &str) -> bool {
    matches!(
        path,
        "/control-plane"
            | "/control-plane/"
            | "/control-plane/endpoints"
            | "/control-plane/connect-tools"
            | "/endpoints"
            | "/control-plane/drafts"
            | "/control-plane/secrets"
    ) || path.starts_with("/control-plane/drafts/")
        || path.starts_with("/control-plane/providers")
        || path.starts_with("/control-plane/accounts")
        || path.starts_with("/control-plane/pools")
        || path.starts_with("/control-plane/policies")
        || path.starts_with("/control-plane/routes")
        || path.starts_with("/control-plane/models")
        || path.starts_with("/control-plane/bindings")
        || path.starts_with("/control-plane/connect-tools")
}

/// Return whether a request is a body-bearing structured mutation.
pub(crate) fn is_control_plane_mutation(method: &Method, path: &str) -> bool {
    is_control_plane_path(path) && matches!(*method, Method::POST | Method::PATCH | Method::DELETE)
}

/// Parse a resource path into an existing typed configuration patch.
///
/// The draft ID is carried in the URL so every resource mutation remains
/// owner-scoped and uses the normal configuration ETag.  No secret value is
/// accepted here; callers first ingest one through `/control-plane/secrets`.
pub(crate) fn resource_patch(
    method: &Method,
    path: &str,
    body: &[u8],
    active: &CompiledConfig,
) -> Result<(u64, TypedConfigPatch), ResourceMutationError> {
    let segments = path
        .strip_prefix("/control-plane/drafts/")
        .ok_or(ResourceMutationError::Unsupported)?
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let draft_id = segments
        .first()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(ResourceMutationError::Invalid)?;
    let operation = segments.get(1).copied().unwrap_or_default();

    if matches!(operation, "validate" | "commit" | "diff") || segments.len() == 1 {
        return Err(ResourceMutationError::Unsupported);
    }

    let direct_resource = RESOURCE_SECTIONS
        .iter()
        .any(|(name, _, _)| *name == operation);
    if direct_resource
        && segments.get(2).is_some_and(|value| {
            matches!(
                *value,
                "reorder"
                    | "combine"
                    | "discover_models"
                    | "select_all_models"
                    | "select_none_models"
            )
        })
    {
        return Err(ResourceMutationError::Unsupported);
    }
    if direct_resource && segments.len() > 3 {
        return Err(ResourceMutationError::Unsupported);
    }
    let resource = if direct_resource {
        operation
    } else {
        segments.get(2).copied().unwrap_or_default()
    };
    let (section, config_section, list_section) = RESOURCE_SECTIONS
        .iter()
        .find(|(name, _, _)| *name == resource)
        .copied()
        .ok_or(ResourceMutationError::Unsupported)?;
    let id_index = if direct_resource { 2 } else { 3 };
    let id_from_path = segments.get(id_index).map(|value| decode_component(value));
    if id_from_path.is_some() && id_from_path.as_ref().is_some_and(|value| value.is_empty()) {
        return Err(ResourceMutationError::Invalid);
    }

    if *method == Method::DELETE {
        let id = id_from_path.ok_or(ResourceMutationError::Invalid)?;
        return Ok((
            draft_id,
            TypedConfigPatch::Remove {
                section: config_section.to_owned(),
                id,
            },
        ));
    }

    let mut value =
        serde_json::from_slice::<Value>(body).map_err(|_| ResourceMutationError::Invalid)?;
    let object = value
        .as_object_mut()
        .ok_or(ResourceMutationError::Invalid)?;
    reject_secret_values(object)?;

    let creating = id_from_path.is_none();
    let id = if resource == "bindings" {
        object
            .get("model_id")
            .or_else(|| object.get("model"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(ResourceMutationError::Invalid)?
    } else {
        id_from_path
            .or_else(|| object.get("id").and_then(Value::as_str).map(str::to_owned))
            .ok_or(ResourceMutationError::Invalid)?
    };
    if matches!(resource, "models" | "bindings") {
        ModelId::new(id.clone()).map_err(|_| ResourceMutationError::Invalid)?;
    } else {
        validate_component(&id)?;
    }
    if list_section {
        let current_id = object.get("id").and_then(Value::as_str);
        if current_id.is_some() && current_id != Some(id.as_str()) {
            return Err(ResourceMutationError::Invalid);
        }
        object.insert("id".to_owned(), Value::String(id.clone()));
    } else {
        object.remove("id");
    }

    match resource {
        "providers" => normalize_provider(object)?,
        "accounts" => normalize_account(object)?,
        "pools" => normalize_pool(object)?,
        "policies" => normalize_policy(object)?,
        "routes" => normalize_route(object)?,
        "models" => normalize_model(object)?,
        "bindings" => {}
        _ => return Err(ResourceMutationError::Unsupported),
    }

    let value = if resource == "bindings" {
        let target = object
            .get("target")
            .cloned()
            .or_else(|| object.get("value").cloned())
            .ok_or(ResourceMutationError::Invalid)?;
        let mut model = Map::new();
        model.insert("id".to_owned(), Value::String(id.clone()));
        model.insert("targets".to_owned(), Value::Array(vec![target]));
        Value::Object(model)
    } else {
        value
    };

    // Create calls fail deterministically when a live resource with the same
    // ID exists. Updates are explicit PATCH calls and are allowed to replace
    // the draft value under its ETag.
    if *method == Method::POST && creating && resource_exists(active, section, &id) {
        return Err(ResourceMutationError::Conflict);
    }

    Ok((
        draft_id,
        TypedConfigPatch::Upsert {
            section: config_section.to_owned(),
            id,
            value,
        },
    ))
}

/// Parse a full model/pool value for convenience operations such as reorder
/// and combine. The operation stays a typed upsert; it never mutates live
/// state or creates an implicit route.
pub(crate) fn convenience_patch(
    _method: &Method,
    path: &str,
    body: &[u8],
    _active: &CompiledConfig,
) -> Result<(u64, TypedConfigPatch), ResourceMutationError> {
    let segments = path
        .strip_prefix("/control-plane/drafts/")
        .ok_or(ResourceMutationError::Unsupported)?
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let draft_id = segments
        .first()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(ResourceMutationError::Invalid)?;
    let resource_name = segments.get(1).copied().unwrap_or_default();
    let (resource_id, operation) = if matches!(
        resource_name,
        "discover_models" | "select_all_models" | "select_none_models"
    ) {
        (None, resource_name)
    } else if matches!(resource_name, "models" | "pools") {
        let candidate = segments.get(2).copied().unwrap_or_default();
        if matches!(
            candidate,
            "discover_models" | "select_all_models" | "select_none_models"
        ) {
            (None, candidate)
        } else {
            (
                Some(candidate),
                segments.get(3).copied().unwrap_or_default(),
            )
        }
    } else {
        (None, segments.get(2).copied().unwrap_or_default())
    };
    if !matches!(
        operation,
        "reorder" | "combine" | "discover_models" | "select_all_models" | "select_none_models"
    ) {
        return Err(ResourceMutationError::Unsupported);
    }
    let body = serde_json::from_slice::<Value>(body).map_err(|_| ResourceMutationError::Invalid)?;
    let value = body
        .get("value")
        .cloned()
        .or_else(|| body.get("resource").cloned())
        .unwrap_or(body);
    reject_secret_object(&value)?;

    let (section, id, value) = match operation {
        "reorder" => {
            let id = resource_id
                .map(decode_component)
                .filter(|value| !value.is_empty())
                .ok_or(ResourceMutationError::Invalid)?;
            let value = value.as_object().ok_or(ResourceMutationError::Invalid)?;
            if !value.contains_key("targets") && !value.contains_key("order") {
                return Err(ResourceMutationError::Invalid);
            }
            ("models", id, Value::Object(value.clone()))
        }
        "combine" => {
            let id = resource_id
                .map(decode_component)
                .filter(|value| !value.is_empty())
                .ok_or(ResourceMutationError::Invalid)?;
            let object = value.as_object().ok_or(ResourceMutationError::Invalid)?;
            if !object.contains_key("accounts") {
                return Err(ResourceMutationError::Invalid);
            }
            ("pools", id, Value::Object(object.clone()))
        }
        "discover_models" | "select_all_models" | "select_none_models" => {
            let mut object = value
                .as_object()
                .cloned()
                .ok_or(ResourceMutationError::Invalid)?;
            let id = object
                .get("id")
                .and_then(Value::as_str)
                .or_else(|| object.get("source_id").and_then(Value::as_str))
                .unwrap_or("catalog")
                .to_owned();
            object.remove("id");
            object.remove("source_id");
            ("catalog", id, Value::Object(object))
        }
        _ => unreachable!(),
    };

    let value = match section {
        "models" => {
            let mut object = value
                .as_object()
                .cloned()
                .ok_or(ResourceMutationError::Invalid)?;
            normalize_model(&mut object)?;
            Value::Object(object)
        }
        "pools" => {
            let mut object = value
                .as_object()
                .cloned()
                .ok_or(ResourceMutationError::Invalid)?;
            normalize_pool(&mut object)?;
            Value::Object(object)
        }
        "catalog" => {
            if !value.is_object() {
                return Err(ResourceMutationError::Invalid);
            }
            value
        }
        _ => return Err(ResourceMutationError::Unsupported),
    };

    let patch = if section == "catalog" {
        TypedConfigPatch::Replace {
            section: section.to_owned(),
            value,
        }
    } else {
        TypedConfigPatch::Upsert {
            section: if section == "pools" {
                "account_pools".to_owned()
            } else {
                section.to_owned()
            },
            id,
            value,
        }
    };
    Ok((draft_id, patch))
}

/// Build the complete redacted graph for one immutable runtime snapshot.
pub(crate) fn control_plane_graph(
    snapshot: &ConfigSnapshot<CompiledConfig>,
    pooling: &PoolingCoordinator,
    catalog: Option<&CatalogRuntime>,
    active_status: Option<Value>,
) -> Value {
    let config = snapshot.config();
    let generation = snapshot.generation().value();
    let states = pooling
        .credential_states()
        .unwrap_or_default()
        .into_iter()
        .map(|state| (state.credential_id.clone(), state))
        .collect::<BTreeMap<_, _>>();
    let health = pooling
        .credential_health_states()
        .unwrap_or_default()
        .into_iter()
        .map(|state| (state.credential_id.clone(), state))
        .collect::<BTreeMap<_, _>>();

    let providers = config
        .upstreams()
        .iter()
        .map(|(id, provider)| {
            let origin = provider.url().origin().ascii_serialization();
            let accounts = config
                .accounts()
                .values()
                .filter(|account| account.provider() == id.as_ref())
                .count();
            let pools = config
                .account_pools()
                .values()
                .filter(|pool| pool.provider() == id.as_ref())
                .count();
            let oauth_capable = provider.oauth().is_some()
                || provider
                    .native()
                    .is_some_and(|native| matches!(native.kind(), "codex" | "palantir_aip"));
            let value = json!({
                "id": id.as_ref(),
                "instance_id": id.as_ref(),
                "revision": revision("provider", id, generation, provider.url().as_str()),
                "origin": origin,
                "base_url": provider.url().as_str(),
                "transport": provider.transport(),
                "known_provider": provider.known_provider(),
                "auth_methods": if oauth_capable { vec!["oauth"] } else { vec!["api_key"] },
                "auth": provider.auth().map(|auth| json!({
                    "required": true,
                    "kind": auth.kind(),
                    "header": auth.header(),
                })).unwrap_or_else(|| json!({"required": false})),
                "oauth": provider.oauth().map(|oauth| json!({
                    "configured": true,
                    "grant_type": oauth.grant_type().as_str(),
                    "client_id_configured": !oauth.client_id().is_empty(),
                    "authorization_endpoint": oauth.authorization_endpoint().as_str(),
                    "token_endpoint": oauth.token_endpoint().as_str(),
                })),
                "native": provider.native().map(|native| json!({"kind": native.kind()})),
                "accounts": accounts,
                "pools": pools,
            });
            value
        })
        .collect::<Vec<_>>();

    let accounts = config
        .accounts()
        .values()
        .map(|account| {
            let state = states.get(account.id());
            let health_state = health.get(account.id());
            let mut value = json!({
                "id": account.id(),
                "revision": revision("account", account.id(), generation, account.provider()),
                "provider": account.provider(),
                "auth_kind": account.auth_kind().as_str(),
                "enabled": state.map_or(account.enabled(), |state| state.enabled),
                "weight": account.weight(),
                "max_concurrency": account.max_concurrency(),
                "quota_project_configured": account.quota_project().is_some(),
                "secret": {
                    "configured": account.secret().is_some(),
                    "kind": account.secret().map_or("none", pooler_config::SecretRef::kind),
                    "opaque": account.secret().is_some_and(|secret| secret.kind() == "managed"),
                },
                "health": health_state.map(|state| json!({
                    "status": format!("{:?}", state.status).to_ascii_lowercase(),
                    "failure_count": state.failure_count,
                    "cooldown_until": state.cooldown_until,
                    "updated_at": state.updated_at,
                })).unwrap_or_else(|| json!({"status": "unknown"})),
            });
            if let Some(state) = state {
                value["store_revision"] = json!(state.revision);
                value["updated_at"] = json!(state.updated_at);
            }
            value
        })
        .collect::<Vec<_>>();

    let pools = config
        .account_pools()
        .values()
        .map(|pool| {
            json!({
                "id": pool.id(),
                "revision": revision("pool", pool.id(), generation, pool.provider()),
                "provider": pool.provider(),
                "strategy": pool.strategy().as_str(),
                "accounts": pool.accounts().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                "homogeneous": pool.accounts().iter().all(|account| {
                    config.accounts().get(account).is_some_and(|account| account.provider() == pool.provider())
                }),
            })
        })
        .collect::<Vec<_>>();

    let policies = config
        .policies()
        .values()
        .map(|policy| {
            let selection = policy.selection();
            let retry = policy.retry();
            let routing = policy.routing();
            json!({
                "id": policy.id(),
                "revision": revision("policy", policy.id(), generation, policy.id()),
                "selection": {
                    "strategy": selection.strategy().as_str(),
                    "affinity": selection.affinity().map(|affinity| json!({
                        "key": affinity.key(), "ttl_ms": affinity.ttl().as_millis(), "rebind": affinity.rebind()
                    })),
                },
                "retry": {
                    "maximum_attempts": retry.maximum_attempts(),
                    "maximum_credentials": retry.maximum_credentials(),
                    "maximum_upstreams": retry.maximum_upstreams(),
                    "before_commit_only": retry.before_commit_only(),
                },
                "routing": {
                    "order": routing.order().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                    "allow": routing.allow().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                    "deny": routing.deny().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                    "allow_fallbacks": routing.allow_fallbacks(),
                    "required_parameters": routing.required_parameters().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                    "minimum_context": routing.minimum_context(),
                    "quantization": routing.quantization().iter().map(AsRef::as_ref).collect::<Vec<_>>(), "privacy": routing.privacy(),
                    "require_zdr": routing.require_zdr(), "data_policy": routing.data_policy(),
                    "max_price": routing.max_price(),
                },
            })
        })
        .collect::<Vec<_>>();

    let models = config
        .models()
        .values()
        .map(|model| model_value(model, generation, &states, &health, config))
        .collect::<Vec<_>>();
    let bindings = config
        .models()
        .values()
        .flat_map(|model| {
            model
                .targets()
                .iter()
                .map(move |target| binding_value(model, target, generation))
        })
        .collect::<Vec<_>>();
    let effective_order = config
        .models()
        .values()
        .map(|model| {
            let mut targets = model.targets().iter().collect::<Vec<_>>();
            targets
                .sort_by_key(|target| (target.priority(), target.binding_id().as_str().to_owned()));
            json!({
                "model": model.id(),
                "candidates": targets.into_iter().enumerate().map(|(index, target)| json!({
                    "position": index + 1,
                    "binding_id": target.binding_id().as_str(),
                    "provider": target.provider(),
                    "priority": target.priority(),
                    "account": target.account(),
                    "account_pool": target.account_pool(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    let cooldowns = pooling.cooldowns().unwrap_or_default();
    let quotas = pooling.quota_states().unwrap_or_default();
    let decisions = pooling.recent_decisions(32).unwrap_or_default();
    let catalog_value = merged_model_catalog_value(config, catalog);
    let discovery = json!({
        "configured": config.catalog().is_some(),
        "catalog_generation": catalog_value["catalog_generation"],
        "refreshed_at_unix_ms": catalog_value["catalog_refreshed_at_unix_ms"],
        "sources": catalog_value["catalog_sources"],
        "models": catalog_value["models"],
    });
    let mut provider_templates = vec![
        json!({
            "id": "openai-subscription",
            "name": "OpenAI subscription (ChatGPT)",
            "base_url": "Managed by Pooler",
            "known_provider": "openai",
            "auth_methods": ["oauth"],
            "native_kind": "codex",
            "native_config": true,
            "model_discovery": true,
            "request_dialect": "openai_responses",
            "endpoint_families": ["models", "responses", "image_generations"],
        }),
        json!({
            "id": "palantir-aip",
            "name": "Palantir AIP",
            "base_url": "Your Foundry enrollment",
            "auth_methods": ["oauth"],
            "native_kind": "palantir_aip",
            "dynamic_origin": true,
            "requires_client_id": true,
            "model_discovery": false,
            "request_dialect": "multi_protocol",
            "endpoint_families": ["chat_completions", "responses", "messages"],
        }),
    ];
    provider_templates.extend(ProviderCatalog::builtin().iter().map(|(id, provider)| {
        json!({
            "id": id,
            "name": provider.name.as_str(),
            "base_url": provider.base_url.as_str(),
            "known_provider": id,
            "auth_methods": ["api_key"],
            "auth_kind": provider.integration.auth_kind.as_str(),
            "model_discovery": provider.integration.discovery_parser.is_some(),
            "request_dialect": provider.integration.request_dialect.as_str(),
            "endpoint_families": provider.integration.endpoint_families,
            "native_kind": provider.integration.native_kind.as_str(),
            "native_config": false,
        })
    }));
    let endpoints = endpoint_inventory(config);
    let routes = endpoints["listeners"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|listener| listener["routes"].as_array().into_iter().flatten().cloned())
        .collect::<Vec<_>>();

    json!({
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "configuration": {
            "generation": generation,
            "active": active_status,
        },
        "providers": providers,
        "provider_templates": provider_templates,
        "accounts": accounts,
        "pools": pools,
        "policies": policies,
        "routes": routes,
        "models": models,
        "bindings": bindings,
        "effective_order": effective_order,
        "discovery": discovery,
        "health": {
            "credentials": health.values().map(|state| json!({
                "account": state.credential_id,
                "status": format!("{:?}", state.status).to_ascii_lowercase(),
                "failure_count": state.failure_count,
                "cooldown_until": state.cooldown_until,
            })).collect::<Vec<_>>(),
            "cooldowns": cooldowns,
        },
        "quota": quotas,
        "recent_failover_and_rebind": decisions,
        "endpoints": endpoints,
    })
}

/// Return every configured listener route without requiring a named client
/// helper.  This is also used by the CLI's offline endpoint inventory.
pub(crate) fn endpoint_inventory(config: &CompiledConfig) -> Value {
    let listeners = config
        .listeners()
        .values()
        .map(|listener| {
            let base_urls = if listener.bind().starts_with('/') {
                Vec::new()
            } else {
                vec![format!("http://{}", listener.bind())]
            };
            let routes = config
                .routes()
                .iter()
                .filter(|route| route.listener() == listener.id())
                .map(|route| {
                    json!({
                        "id": route.id(),
                        "methods": route.matcher().methods().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                        "path": route.matcher().path().value(),
                        "protocol": route.ingress().mode(),
                        "downstream_auth": route.downstream_auth().map(|auth| json!({
                            "required": true,
                            "kind": auth.kind(),
                            "header": auth.header(),
                        })).unwrap_or_else(|| json!({"required": false})),
                        "target": route.target().upstream(),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "id": listener.id(),
                "bind": listener.bind(),
                "base_urls": base_urls,
                "routes": routes,
            })
        })
        .collect::<Vec<_>>();
    let management = config.management().map(|management| {
        json!({
            "bind": management.bind(),
            "base_urls": if management.bind().starts_with('/') { Vec::<String>::new() } else { vec![format!("http://{}", management.bind())] },
            "paths": ["/management/control-plane", "/management/endpoints", "/management/session"],
            "auth": {"required": management.auth().is_some(), "scheme": "Bearer"},
        })
    });
    json!({
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "client_agnostic": true,
        "listeners": listeners,
        "management": management,
        "downstream_clients": [
            "Factory Droid", "Vercel fx", "Devin", "Codex", "Claude Code", "Cursor", "generic SDK"
        ],
        "custom_provider_origins": config.upstreams().values().map(|provider| provider.url().origin().ascii_serialization()).collect::<BTreeSet<_>>(),
        "connect_tools": {
            "optional": true,
            "routing_effect": "none",
            "namespace": "/management/control-plane/connect-tools",
            "requires_confirmation_for_route_draft": true,
        },
    })
}

fn model_value(
    model: &ModelPlan,
    generation: u64,
    states: &BTreeMap<String, pooler_store::CredentialState>,
    health: &BTreeMap<String, pooler_store::CredentialHealthState>,
    config: &CompiledConfig,
) -> Value {
    let targets = model
        .targets()
        .iter()
        .map(|target| {
            let eligible = target_accounts(target, config).iter().any(|account| {
                states.get(*account).is_none_or(|state| state.enabled)
                    && health
                        .get(*account)
                        .is_none_or(|state| !matches!(format!("{:?}", state.status).as_str(), "Disabled" | "CoolingDown"))
            });
            json!({
                "binding_id": target.binding_id().as_str(),
                "provider": target.provider(), "account": target.account(), "account_pool": target.account_pool(),
                "priority": target.priority(), "weight": target.weight(),
                "upstream_model": target.upstream_model(), "wire_family": target.wire_family(),
                "eligible": eligible,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "id": model.id(),
        "revision": revision("model", model.id(), generation, &targets.len().to_string()),
        "targets": targets,
    })
}

fn binding_value(model: &ModelPlan, target: &ModelTargetPlan, generation: u64) -> Value {
    let binding_id = target.binding_id().as_str();
    json!({
        "id": target.id(),
        "binding_id": binding_id,
        "model": model.id(),
        "provider": target.provider(),
        "account": target.account(),
        "account_pool": target.account_pool(),
        "priority": target.priority(),
        "weight": target.weight(),
        "upstream_model": target.upstream_model(),
        "wire_family": target.wire_family(),
        "revision": revision("binding", &binding_id, generation, target.upstream_model()),
    })
}

fn target_accounts<'a>(target: &'a ModelTargetPlan, config: &'a CompiledConfig) -> Vec<&'a str> {
    if let Some(account) = target.account() {
        return vec![account];
    }
    target
        .account_pool()
        .and_then(|pool| config.account_pools().get(pool))
        .map(|pool| {
            pool.accounts()
                .iter()
                .map(|account| account.as_ref())
                .collect()
        })
        .unwrap_or_default()
}

fn resource_exists(config: &CompiledConfig, section: &str, id: &str) -> bool {
    match section {
        "providers" => config.upstreams().contains_key(id),
        "accounts" => config.accounts().contains_key(id),
        "pools" => config.account_pools().contains_key(id),
        "policies" => config.policies().contains_key(id),
        "routes" => config.route(id).is_some(),
        "models" | "bindings" => config.models().contains_key(id),
        _ => false,
    }
}

fn normalize_provider(object: &mut Map<String, Value>) -> Result<(), ResourceMutationError> {
    if object.get("url").is_none() {
        if let Some(base_url) = object.remove("base_url") {
            object.insert("url".to_owned(), base_url);
        }
    }
    if object.get("url").and_then(Value::as_str).is_none()
        && object
            .get("known_provider")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(ResourceMutationError::Invalid);
    }
    let openai_compatible = object
        .get("native")
        .and_then(Value::as_object)
        .and_then(|native| native.get("kind"))
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.eq_ignore_ascii_case("openai_compatible"));
    if openai_compatible {
        let url = object
            .get("url")
            .and_then(Value::as_str)
            .and_then(|value| Url::parse(value).ok())
            .ok_or(ResourceMutationError::Invalid)?;
        OpenAiCompatibleAdapter::new(
            "custom",
            url,
            AuthPlacement::Bearer,
            [ProviderOperation::ChatCompletions],
        )
        .map_err(|_| ResourceMutationError::Invalid)?;
    }
    Ok(())
}

fn normalize_account(object: &mut Map<String, Value>) -> Result<(), ResourceMutationError> {
    let secret = object.remove("managed_secret_id");
    if object.get("secret").is_none() {
        if let Some(secret) = secret {
            let id = secret
                .as_str()
                .ok_or(ResourceMutationError::SecretReferenceRequired)?;
            let id = id.strip_prefix("managed:").unwrap_or(id);
            validate_component(id)?;
            object.insert("secret".to_owned(), Value::String(format!("managed:{id}")));
        }
    }
    if let Some(secret) = object.get("secret") {
        let reference = secret
            .as_str()
            .ok_or(ResourceMutationError::SecretReferenceRequired)?;
        if !reference.starts_with("managed:") {
            return Err(ResourceMutationError::SecretReferenceRequired);
        }
    }
    if object.get("provider").and_then(Value::as_str).is_none() {
        return Err(ResourceMutationError::Invalid);
    }
    Ok(())
}

fn normalize_pool(object: &mut Map<String, Value>) -> Result<(), ResourceMutationError> {
    let provider = object.get("provider").and_then(Value::as_str);
    let accounts = object.get("accounts").and_then(Value::as_array);
    if provider.is_none()
        || accounts.is_none()
        || accounts.is_some_and(|accounts| accounts.is_empty())
    {
        return Err(ResourceMutationError::Invalid);
    }
    if accounts.is_some_and(|accounts| accounts.iter().any(|account| account.as_str().is_none())) {
        return Err(ResourceMutationError::Invalid);
    }
    Ok(())
}

fn normalize_policy(object: &mut Map<String, Value>) -> Result<(), ResourceMutationError> {
    if !object.contains_key("selection")
        && !object.contains_key("retry")
        && !object.contains_key("routing")
    {
        return Err(ResourceMutationError::Invalid);
    }
    Ok(())
}

fn normalize_route(object: &mut Map<String, Value>) -> Result<(), ResourceMutationError> {
    if object.get("listen").and_then(Value::as_str).is_none()
        || object.get("match").and_then(Value::as_object).is_none()
        || object.get("target").is_none()
    {
        return Err(ResourceMutationError::Invalid);
    }
    Ok(())
}

fn normalize_model(object: &mut Map<String, Value>) -> Result<(), ResourceMutationError> {
    if object.get("targets").and_then(Value::as_array).is_none() {
        return Err(ResourceMutationError::Invalid);
    }
    Ok(())
}

fn reject_secret_values(object: &Map<String, Value>) -> Result<(), ResourceMutationError> {
    for (key, value) in object {
        if matches!(
            key.as_str(),
            "secret_value" | "client_secret" | "access_token" | "refresh_token" | "password"
        ) && value
            .as_str()
            .is_none_or(|value| !value.starts_with("managed:"))
        {
            return Err(ResourceMutationError::SecretReferenceRequired);
        }
        if key == "secret" && !value.is_string() {
            return Err(ResourceMutationError::SecretReferenceRequired);
        }
        if value.is_object() {
            reject_secret_object(value)?;
        } else if let Some(values) = value.as_array() {
            for value in values {
                reject_secret_object(value)?;
            }
        }
    }
    Ok(())
}

fn reject_secret_object(value: &Value) -> Result<(), ResourceMutationError> {
    if let Some(object) = value.as_object() {
        reject_secret_values(object)
    } else {
        Ok(())
    }
}

fn validate_component(value: &str) -> Result<(), ResourceMutationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(ResourceMutationError::Invalid)
    } else {
        Ok(())
    }
}

fn decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = bytes[index + 1];
            let low = bytes[index + 2];
            let parse = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            if let (Some(high), Some(low)) = (parse(high), parse(low)) {
                decoded.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(decoded).unwrap_or_default()
}

fn revision(kind: &str, id: &str, generation: u64, value: &str) -> String {
    let input = format!("pooler-control-plane:v2|{kind}|{id}|{generation}|{value}");
    digest(&SHA256, input.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active() -> CompiledConfig {
        pooler_config::compile_yaml(
            "resource-test.yaml",
            "version: 2\nlisteners: {inference: {bind: 127.0.0.1:0}}\nupstreams: {anchor: {url: https://api.example.com/v1}}\n",
        )
        .expect("active config")
    }

    #[test]
    fn route_resources_are_typed_and_catalog_operations_drop_transport_ids() {
        let (_, route) = resource_patch(
            &Method::POST,
            "/control-plane/drafts/1/routes",
            br#"{"id":"standard-models","listen":"inference","match":{"methods":["GET"],"path":"/v1/models"},"serve":"model_catalog","ingress":{"mode":"opaque"},"target":{"provider":"anchor"},"response":{"mode":"opaque"}}"#,
            &active(),
        )
        .expect("route patch");
        assert!(matches!(
            route,
            TypedConfigPatch::Upsert { ref section, ref id, .. }
                if section == "routes" && id == "standard-models"
        ));

        let (_, catalog) = convenience_patch(
            &Method::POST,
            "/control-plane/drafts/1/models/select_all_models",
            br#"{"id":"catalog","sources":[],"overrides":[]}"#,
            &active(),
        )
        .expect("catalog patch");
        let TypedConfigPatch::Replace { section, value } = catalog else {
            panic!("catalog replace patch");
        };
        assert_eq!(section, "catalog");
        assert!(value.get("id").is_none());

        let (_, model) = resource_patch(
            &Method::POST,
            "/control-plane/drafts/1/models",
            br#"{"id":"anthropic/claude-test","targets":[]}"#,
            &active(),
        )
        .expect("namespaced model patch");
        assert!(matches!(
            model,
            TypedConfigPatch::Upsert { ref section, ref id, .. }
                if section == "models" && id == "anthropic/claude-test"
        ));
    }

    #[test]
    fn custom_provider_urls_require_https_or_explicit_loopback_http() {
        let active = active();
        let rejected = resource_patch(
            &Method::POST,
            "/control-plane/drafts/1/providers",
            br#"{"id":"custom","url":"http://example.com/v1","native":{"kind":"openai_compatible"}}"#,
            &active,
        );
        assert!(matches!(rejected, Err(ResourceMutationError::Invalid)));
        for url in ["https://example.com/v1", "http://127.0.0.1:9000/v1"] {
            let body = format!(
                r#"{{"id":"custom","url":"{url}","native":{{"kind":"openai_compatible"}}}}"#
            );
            resource_patch(
                &Method::POST,
                "/control-plane/drafts/1/providers",
                body.as_bytes(),
                &active,
            )
            .expect("safe custom provider");
        }
    }
}
