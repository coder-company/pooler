//! Deterministic JSON Schema for the source configuration.
//!
//! The runtime parser remains the authority for YAML syntax and semantic
//! validation.  This schema is a stable editor and release artifact: it
//! describes the fields accepted by the strict source declarations and the
//! loader's import/overlay controls.  `render_config_schema` is intentionally
//! generated from small, typed helpers so the checked-in artifact can be
//! compared byte-for-byte in tests and CI.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use pooler_core::Capability;

/// Version of the generated JSON Schema document.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Returns the source-configuration JSON Schema.
#[must_use]
pub fn config_schema() -> Value {
    let mut definitions = BTreeMap::new();
    definitions.insert("account".to_owned(), account_schema());
    definitions.insert("account_pool".to_owned(), account_pool_schema());
    definitions.insert("affinity".to_owned(), affinity_schema());
    definitions.insert("auth".to_owned(), auth_schema());
    definitions.insert("body".to_owned(), body_schema());
    definitions.insert("cooldown".to_owned(), cooldown_schema());
    definitions.insert("duration".to_owned(), duration_schema());
    definitions.insert("extension".to_owned(), extension_schema());
    definitions.insert("extension_limits".to_owned(), extension_limits_schema());
    definitions.insert("import".to_owned(), import_schema());
    definitions.insert("listener".to_owned(), listener_schema());
    definitions.insert(
        "listener_client_auth".to_owned(),
        listener_client_auth_schema(),
    );
    definitions.insert("listener_tls".to_owned(), listener_tls_schema());
    definitions.insert("management".to_owned(), management_schema());
    definitions.insert("match".to_owned(), match_schema());
    definitions.insert("model".to_owned(), model_schema());
    definitions.insert("model_target".to_owned(), model_target_schema());
    definitions.insert("native".to_owned(), native_schema());
    definitions.insert("oauth".to_owned(), oauth_schema());
    definitions.insert("policy".to_owned(), policy_schema());
    definitions.insert("request".to_owned(), request_schema());
    definitions.insert("request_step".to_owned(), request_step_schema());
    definitions.insert("retry".to_owned(), retry_schema());
    definitions.insert("route".to_owned(), route_schema());
    definitions.insert("route_limits".to_owned(), route_limits_schema());
    definitions.insert("secret_ref".to_owned(), secret_ref_schema());
    definitions.insert("selection".to_owned(), selection_schema());
    definitions.insert("stream".to_owned(), stream_schema());
    definitions.insert("target".to_owned(), target_schema());
    definitions.insert(
        "transform_parameters".to_owned(),
        transform_parameters_schema(),
    );
    definitions.insert("transport".to_owned(), transport_schema());
    definitions.insert("upstream".to_owned(), upstream_schema());

    let mut properties = BTreeMap::new();
    properties.insert("version", integer_schema(Some(1), Some(1)));
    properties.insert("listeners", named_map_schema(reference("listener")));
    properties.insert("upstreams", named_map_schema(reference("upstream")));
    properties.insert("providers", named_map_schema(reference("upstream")));
    properties.insert("models", array_schema(reference("model"), Some(0), None));
    properties.insert("accounts", named_map_schema(reference("account")));
    properties.insert("credentials", named_map_schema(reference("account")));
    properties.insert("account_pools", named_map_schema(reference("account_pool")));
    properties.insert("pools", named_map_schema(reference("account_pool")));
    properties.insert("policies", named_map_schema(reference("policy")));
    properties.insert("routes", array_schema(reference("route"), Some(0), None));
    properties.insert("extensions", named_map_schema(reference("extension")));
    properties.insert("management", reference("management"));
    properties.insert("imports", array_schema(reference("import"), Some(1), None));

    let mut schema = object_schema(properties, &["version"], false);
    let object = schema
        .as_object_mut()
        .expect("object_schema always returns an object");
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String("https://coder-company.github.io/pooler/schemas/config-v1.json".to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Pooler source configuration".to_owned()),
    );
    object.insert(
        "$comment".to_owned(),
        Value::String(
            "Imports and overlay directives are resolved before strict Config parsing; semantic reference and route validation is performed by pooler check.".to_owned(),
        ),
    );
    object.insert("$defs".to_owned(), Value::Object(string_map(definitions)));
    schema
}

/// Renders the schema with stable indentation and a trailing newline.
#[must_use]
pub fn render_config_schema() -> String {
    let mut rendered = serde_json::to_string_pretty(&config_schema())
        .expect("the configuration schema is always serializable");
    rendered.push('\n');
    rendered
}

fn account_schema() -> Value {
    object_schema(
        properties([
            ("provider", optional_string()),
            ("upstream", optional_string()),
            ("secret", optional(reference("secret_ref"))),
            ("enabled", optional(boolean_schema())),
            ("weight", optional(u32_schema())),
            ("max_concurrency", optional(u32_schema())),
        ]),
        &[],
        true,
    )
}

fn account_pool_schema() -> Value {
    object_schema(
        properties([
            ("accounts", array_schema(string_schema(), Some(0), None)),
            ("members", array_schema(string_schema(), Some(0), None)),
        ]),
        &[],
        true,
    )
}

fn affinity_schema() -> Value {
    object_schema(
        properties([
            ("key", optional_string()),
            ("ttl", optional(reference("duration"))),
            ("rebind", optional(boolean_schema())),
        ]),
        &[],
        false,
    )
}

fn auth_schema() -> Value {
    object_schema(
        properties([
            ("kind", optional(string_enum(["bearer", "bearer_secret"]))),
            ("secret", optional(reference("secret_ref"))),
        ]),
        &[],
        false,
    )
}

fn body_schema() -> Value {
    object_schema(
        properties([
            (
                "mode",
                optional(string_enum(["opaque", "inspect", "patch", "semantic"])),
            ),
            ("framing", optional_string()),
            ("decoder", optional_string()),
            ("encoder", optional_string()),
            ("inspectors", array_schema(string_schema(), Some(0), None)),
        ]),
        &[],
        false,
    )
}

fn cooldown_schema() -> Value {
    object_schema(
        properties([
            (
                "scope",
                optional(string_enum([
                    "credential",
                    "credential_model",
                    "model",
                    "provider",
                    "provider_model",
                    "route",
                ])),
            ),
            ("duration", optional(reference("duration"))),
        ]),
        &[],
        false,
    )
}

fn duration_schema() -> Value {
    one_of([
        string_pattern(r"^[0-9]+(ms|s|m|h)$"),
        integer_schema(Some(0), None),
    ])
}

fn extension_schema() -> Value {
    one_of([
        extension_variant_schema("command"),
        extension_variant_schema("wasm"),
    ])
}

fn extension_variant_schema(executable: &str) -> Value {
    let executable: &'static str = if executable == "command" {
        "command"
    } else {
        "wasm"
    };
    let other: &'static str = if executable == "command" {
        "wasm"
    } else {
        "command"
    };
    object_schema(
        properties([
            (executable, nonempty_string()),
            (other, optional_string()),
            ("args", array_schema(string_schema(), Some(0), Some(64))),
            (
                "capabilities",
                array_schema(string_enum(["inspect", "transform"]), Some(1), Some(2)),
            ),
            ("limits", optional(reference("extension_limits"))),
        ]),
        &[executable, "capabilities"],
        false,
    )
}

fn extension_limits_schema() -> Value {
    object_schema(
        properties([
            ("max_input_bytes", optional(u64_schema())),
            ("max_output_bytes", optional(u64_schema())),
            ("timeout", optional(reference("duration"))),
            ("max_memory_bytes", optional(u64_schema())),
            ("max_concurrency", optional(u32_schema())),
        ]),
        &[],
        false,
    )
}

fn import_schema() -> Value {
    let file = object_schema(properties([("file", nonempty_string())]), &["file"], false);
    let overlay = object_schema(
        properties([("overlay", nonempty_string())]),
        &["overlay"],
        false,
    );
    let preset = object_schema(
        properties([
            ("preset", string_enum(["cursor", "devin"])),
            ("as", string_pattern(r"^[A-Za-z0-9._-]{1,128}$")),
            ("with", string_map_schema()),
        ]),
        &["preset"],
        false,
    );
    one_of([file, overlay, preset])
}

fn listener_schema() -> Value {
    object_schema(
        properties([
            ("bind", string_schema()),
            (
                "protocol",
                optional(string_enum([
                    "http1",
                    "http/1.1",
                    "h1",
                    "auto",
                    "http1+http2",
                    "http1-or-http2",
                    "h2c",
                    "http2",
                    "http/2",
                    "h2",
                ])),
            ),
            ("h2c", optional(boolean_schema())),
            ("tls", optional(reference("listener_tls"))),
        ]),
        &[],
        true,
    )
}

fn listener_tls_schema() -> Value {
    object_schema(
        properties([
            ("cert", optional_string()),
            ("certificate", optional_string()),
            ("certificate_file", optional_string()),
            ("cert_file", optional_string()),
            ("key", optional_string()),
            ("private_key", optional_string()),
            ("private_key_file", optional_string()),
            ("key_file", optional_string()),
            (
                "alpn",
                optional(array_schema(string_schema(), Some(1), None)),
            ),
            (
                "alpn_protocols",
                optional(array_schema(string_schema(), Some(1), None)),
            ),
            ("handshake_timeout", optional(reference("duration"))),
            ("client_auth", optional(reference("listener_client_auth"))),
        ]),
        &[],
        false,
    )
}

fn listener_client_auth_schema() -> Value {
    object_schema(
        properties([
            ("ca", optional_string()),
            ("ca_file", optional_string()),
            ("certificate_authority", optional_string()),
            ("required", optional(boolean_schema())),
        ]),
        &[],
        false,
    )
}

fn management_schema() -> Value {
    object_schema(
        properties([
            ("enabled", optional(boolean_schema())),
            ("bind", optional_string()),
            ("listen", optional_string()),
            ("remote", optional(boolean_schema())),
            ("allow_remote", optional(boolean_schema())),
            ("auth", optional(reference("auth"))),
            ("authentication", optional(reference("auth"))),
        ]),
        &[],
        false,
    )
}

fn match_schema() -> Value {
    object_schema(
        properties([
            ("methods", array_schema(string_schema(), Some(0), None)),
            ("method", optional_string()),
            ("host", optional_string()),
            ("path", optional_string()),
            ("path_template", optional_string()),
            ("path_prefix", optional_string()),
            ("headers", string_map_schema()),
            (
                "content_types",
                array_schema(string_schema(), Some(0), None),
            ),
            ("websocket", optional(boolean_schema())),
        ]),
        &[],
        false,
    )
}

fn model_schema() -> Value {
    object_schema(
        properties([
            ("id", string_pattern(r"^[A-Za-z0-9._-]{1,128}$")),
            (
                "targets",
                array_schema(reference("model_target"), Some(0), None),
            ),
        ]),
        &["id"],
        true,
    )
}

fn model_target_schema() -> Value {
    object_schema(
        properties([
            ("provider", optional_string()),
            ("upstream", optional_string()),
            ("upstream_model", optional_string()),
            (
                "capabilities",
                array_schema(
                    string_enum(Capability::ALL.map(Capability::as_str)),
                    Some(0),
                    None,
                ),
            ),
        ]),
        &[],
        false,
    )
}

fn native_schema() -> Value {
    object_schema(
        properties([
            ("kind", optional_string()),
            ("quota_endpoint", optional_string()),
        ]),
        &[],
        false,
    )
}

fn oauth_schema() -> Value {
    object_schema(
        properties([
            ("authorization_endpoint", optional_string()),
            ("token_endpoint", optional_string()),
            ("revocation_endpoint", optional_string()),
            ("revoke_endpoint", optional_string()),
            ("identity_endpoint", optional_string()),
            ("client_id", optional_string()),
            ("scopes", array_schema(string_schema(), Some(0), None)),
            ("callback", optional_string()),
        ]),
        &[],
        false,
    )
}

fn policy_schema() -> Value {
    object_schema(
        properties([
            ("selection", optional(reference("selection"))),
            ("retry", optional(reference("retry"))),
            ("stream", optional(reference("stream"))),
            ("cooldown", optional(reference("cooldown"))),
            ("account_pool", optional_string()),
            ("pool", optional_string()),
        ]),
        &[],
        true,
    )
}

fn request_schema() -> Value {
    object_schema(
        properties([(
            "steps",
            array_schema(reference("request_step"), Some(0), Some(32)),
        )]),
        &[],
        false,
    )
}

fn request_step_schema() -> Value {
    object_schema(
        properties([
            (
                "use",
                string_pattern(
                    r"^(transform\.json\.set|transform\.json\.set_when_model_prefix|transform\.external\.[A-Za-z0-9._-]+)$",
                ),
            ),
            ("with", reference("transform_parameters")),
        ]),
        &["use", "with"],
        false,
    )
}

fn retry_schema() -> Value {
    object_schema(
        properties([
            ("maximum_attempts", optional(u32_schema())),
            ("max_attempts", optional(u32_schema())),
            ("maximum_credentials", optional(u32_schema())),
            ("max_credentials", optional(u32_schema())),
            ("maximum_providers", optional(u32_schema())),
            ("max_providers", optional(u32_schema())),
            ("maximum_elapsed", optional(reference("duration"))),
            ("max_elapsed", optional(reference("duration"))),
            ("maximum_recovery_wait", optional(reference("duration"))),
            ("max_recovery_wait", optional(reference("duration"))),
            ("base_delay", optional(reference("duration"))),
            ("maximum_delay", optional(reference("duration"))),
            ("max_delay", optional(reference("duration"))),
            ("maximum_total_delay", optional(reference("duration"))),
            ("max_total_delay", optional(reference("duration"))),
            ("before_commit_only", optional(boolean_schema())),
            (
                "statuses",
                array_schema(integer_schema(Some(0), Some(599)), Some(0), None),
            ),
            (
                "retryable_statuses",
                array_schema(integer_schema(Some(0), Some(599)), Some(0), None),
            ),
        ]),
        &[],
        false,
    )
}

fn route_schema() -> Value {
    object_schema(
        properties([
            ("id", string_pattern(r"^[A-Za-z0-9._-]{1,128}$")),
            ("listen", optional_string()),
            ("listener", optional_string()),
            ("match", optional(reference("match"))),
            ("downstream_auth", optional(reference("auth"))),
            ("auth", optional(reference("auth"))),
            ("limits", optional(reference("route_limits"))),
            ("ingress", optional(reference("body"))),
            ("request", optional(reference("request"))),
            ("response", optional(reference("body"))),
            (
                "target",
                optional(one_of([string_schema(), reference("target")])),
            ),
            ("policy", optional_string()),
            ("upstream", optional_string()),
            (
                "loss_policy",
                optional(string_enum(["reject", "preserve", "degrade"])),
            ),
            (
                "priority",
                optional(signed_integer_schema(i32::MIN, i32::MAX)),
            ),
        ]),
        &["id"],
        true,
    )
}

fn route_limits_schema() -> Value {
    object_schema(
        properties([
            (
                "max_request_body_bytes",
                optional(integer_schema(Some(0), None)),
            ),
            (
                "max_response_body_bytes",
                optional(integer_schema(Some(0), None)),
            ),
            ("max_header_count", optional(u32_schema())),
            ("max_header_bytes", optional(integer_schema(Some(0), None))),
            ("max_frame_bytes", optional(integer_schema(Some(0), None))),
            ("max_event_bytes", optional(integer_schema(Some(0), None))),
            (
                "max_bootstrap_bytes",
                optional(integer_schema(Some(0), None)),
            ),
            ("max_bootstrap_events", optional(u32_schema())),
            ("max_queue_bytes", optional(integer_schema(Some(0), None))),
            ("max_queue_items", optional(u32_schema())),
            ("request_timeout", optional(reference("duration"))),
            ("connect_timeout", optional(reference("duration"))),
        ]),
        &[],
        false,
    )
}

fn selection_schema() -> Value {
    object_schema(
        properties([
            (
                "strategy",
                optional(string_enum([
                    "round_robin",
                    "smooth_weighted_round_robin",
                    "fill_first",
                    "least_in_flight",
                    "health_weighted",
                    "ordered_fallback",
                ])),
            ),
            ("account_pool", optional_string()),
            ("pool", optional_string()),
            ("accounts", array_schema(string_schema(), Some(0), None)),
            ("session_affinity", optional(reference("duration"))),
            ("affinity", optional(reference("affinity"))),
        ]),
        &[],
        false,
    )
}

fn stream_schema() -> Value {
    object_schema(
        properties([
            ("bootstrap_events", optional(u32_schema())),
            (
                "bootstrap_bytes",
                optional(one_of([
                    integer_schema(Some(0), None),
                    byte_size_string_schema(),
                ])),
            ),
            ("bootstrap_timeout", optional(reference("duration"))),
        ]),
        &[],
        false,
    )
}

fn target_schema() -> Value {
    object_schema(
        properties([
            ("upstream", optional_string()),
            ("provider", optional_string()),
            ("path", optional_string()),
            ("upstream_path", optional_string()),
            ("model_from", optional_string()),
            ("policy", optional_string()),
        ]),
        &[],
        false,
    )
}

fn transform_parameters_schema() -> Value {
    object_schema(
        properties([
            ("pointer", optional_string()),
            ("value", any_schema()),
            ("prefix", optional_string()),
            ("model_prefix", optional_string()),
        ]),
        &["value"],
        false,
    )
}

fn transport_schema() -> Value {
    object_schema(
        properties([
            ("kind", optional_string()),
            ("base_url", optional_string()),
            ("connect_timeout", optional(duration_string_schema())),
            ("request_timeout", optional(duration_string_schema())),
            ("http2", optional(boolean_schema())),
        ]),
        &[],
        false,
    )
}

fn upstream_schema() -> Value {
    object_schema(
        properties([
            ("url", optional_string()),
            ("base_url", optional_string()),
            ("transport", optional(reference("transport"))),
            ("auth", optional(reference("auth"))),
            ("oauth", optional(reference("oauth"))),
            ("native", optional(reference("native"))),
        ]),
        &[],
        true,
    )
}

fn secret_ref_schema() -> Value {
    string_pattern(r"^(env:[A-Za-z_][A-Za-z0-9_]*|file:.+|keyring:[^/]+/.+)$")
}

fn string_map_schema() -> Value {
    let mut schema = BTreeMap::new();
    schema.insert("additionalProperties".to_owned(), string_schema());
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    Value::Object(string_map(schema))
}

fn named_map_schema(value: Value) -> Value {
    let mut schema = BTreeMap::new();
    schema.insert("additionalProperties".to_owned(), value);
    schema.insert("propertyNames".to_owned(), id_schema());
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    Value::Object(string_map(schema))
}

fn object_schema(
    properties: BTreeMap<&'static str, Value>,
    required: &[&'static str],
    directives: bool,
) -> Value {
    let mut properties = properties
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect::<BTreeMap<_, _>>();
    let mut schema = BTreeMap::new();
    if directives {
        properties.insert("merge".to_owned(), Value::Bool(true));
        properties.insert("remove".to_owned(), Value::Bool(true));
        schema.insert(
            "not".to_owned(),
            Value::Object(string_map(BTreeMap::from([(
                "required".to_owned(),
                Value::Array(vec![
                    Value::String("merge".to_owned()),
                    Value::String("remove".to_owned()),
                ]),
            )]))),
        );
    }
    schema.insert("additionalProperties".to_owned(), Value::Bool(false));
    schema.insert(
        "properties".to_owned(),
        Value::Object(string_map(properties)),
    );
    if !required.is_empty() {
        schema.insert(
            "required".to_owned(),
            Value::Array(
                required
                    .iter()
                    .map(|value| Value::String((*value).to_owned()))
                    .collect(),
            ),
        );
    }
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    Value::Object(string_map(schema))
}

fn properties<const N: usize>(
    entries: [(&'static str, Value); N],
) -> BTreeMap<&'static str, Value> {
    entries.into_iter().collect()
}

fn reference(name: &str) -> Value {
    let mut object = Map::new();
    object.insert("$ref".to_owned(), Value::String(format!("#/$defs/{name}")));
    Value::Object(object)
}

fn optional(value: Value) -> Value {
    value
}

fn optional_string() -> Value {
    string_schema()
}

fn nonempty_string() -> Value {
    Value::Object(string_map(BTreeMap::from([
        (
            "minLength".to_owned(),
            Value::Number(serde_json::Number::from(1)),
        ),
        ("type".to_owned(), Value::String("string".to_owned())),
    ])))
}

fn string_schema() -> Value {
    Value::Object(string_map(BTreeMap::from([(
        "type".to_owned(),
        Value::String("string".to_owned()),
    )])))
}

fn string_pattern(pattern: &str) -> Value {
    Value::Object(string_map(BTreeMap::from([
        ("pattern".to_owned(), Value::String(pattern.to_owned())),
        ("type".to_owned(), Value::String("string".to_owned())),
    ])))
}

fn string_enum<const N: usize>(values: [&str; N]) -> Value {
    Value::Object(string_map(BTreeMap::from([
        (
            "enum".to_owned(),
            Value::Array(
                values
                    .into_iter()
                    .map(|value| Value::String(value.to_owned()))
                    .collect(),
            ),
        ),
        ("type".to_owned(), Value::String("string".to_owned())),
    ])))
}

fn integer_schema(minimum: Option<u64>, maximum: Option<u64>) -> Value {
    let mut schema = BTreeMap::new();
    if let Some(minimum) = minimum {
        schema.insert(
            "minimum".to_owned(),
            Value::Number(serde_json::Number::from(minimum)),
        );
    }
    if let Some(maximum) = maximum {
        schema.insert(
            "maximum".to_owned(),
            Value::Number(serde_json::Number::from(maximum)),
        );
    }
    schema.insert("type".to_owned(), Value::String("integer".to_owned()));
    Value::Object(string_map(schema))
}

fn u32_schema() -> Value {
    integer_schema(Some(0), Some(u64::from(u32::MAX)))
}

fn u64_schema() -> Value {
    integer_schema(Some(0), None)
}

fn signed_integer_schema(minimum: i32, maximum: i32) -> Value {
    Value::Object(string_map(BTreeMap::from([
        (
            "maximum".to_owned(),
            Value::Number(serde_json::Number::from(i64::from(maximum))),
        ),
        (
            "minimum".to_owned(),
            Value::Number(serde_json::Number::from(i64::from(minimum))),
        ),
        ("type".to_owned(), Value::String("integer".to_owned())),
    ])))
}

fn boolean_schema() -> Value {
    Value::Object(string_map(BTreeMap::from([(
        "type".to_owned(),
        Value::String("boolean".to_owned()),
    )])))
}

fn any_schema() -> Value {
    Value::Object(Map::new())
}

fn array_schema(items: Value, minimum: Option<u64>, maximum: Option<u64>) -> Value {
    let mut schema = BTreeMap::new();
    schema.insert("items".to_owned(), items);
    if let Some(minimum) = minimum {
        schema.insert(
            "minItems".to_owned(),
            Value::Number(serde_json::Number::from(minimum)),
        );
    }
    if let Some(maximum) = maximum {
        schema.insert(
            "maxItems".to_owned(),
            Value::Number(serde_json::Number::from(maximum)),
        );
    }
    schema.insert("type".to_owned(), Value::String("array".to_owned()));
    Value::Object(string_map(schema))
}

fn one_of(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Object(string_map(BTreeMap::from([(
        "oneOf".to_owned(),
        Value::Array(values.into_iter().collect()),
    )])))
}

fn byte_size_string_schema() -> Value {
    string_pattern(r"^\s*[0-9]+(b|kb|kib|mb|mib|gb|gib)\s*$")
}

fn duration_string_schema() -> Value {
    string_pattern(r"^[0-9]+(ms|s|m|h)$")
}

fn id_schema() -> Value {
    string_pattern(r"^[A-Za-z0-9._-]{1,128}$")
}

fn string_map(values: BTreeMap<String, Value>) -> Map<String, Value> {
    values
        .into_iter()
        .fold(Map::new(), |mut object, (key, value)| {
            object.insert(key, value);
            object
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    #[test]
    fn schema_is_deterministic_and_strict_at_each_object_boundary() {
        let first = render_config_schema();
        assert_eq!(first, render_config_schema());
        assert!(first.contains("\"additionalProperties\": false"));
        assert!(first.contains("\"imports\""));
        assert!(first.contains("\"providers\""));
        assert!(first.contains("keyring:[^/]+/.+"));
    }

    #[test]
    fn checked_in_schema_matches_the_generator() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schema/pooler.schema.json");
        let expected = fs::read_to_string(path).expect("checked-in schema is readable");
        assert_eq!(expected, render_config_schema());
    }
}
