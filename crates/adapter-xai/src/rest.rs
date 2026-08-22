use pooler_protocol::{
    ConversionError, ConversionReport, LossPolicy, OpenAiChatCodec, OpenAiChatError,
    SemanticRequest,
};
use serde_json::{Map, Value};
use thiserror::Error;

/// xAI JSON endpoint prepared by the REST adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XaiRestEndpoint {
    /// `POST /v1/chat/completions`.
    ChatCompletions,
    /// `POST /v1/responses`.
    Responses,
    /// `POST /v1/responses/compact`.
    ResponsesCompact,
}

/// Transport carrying a Responses request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum XaiRestTransport {
    /// Ordinary HTTP request/response transport.
    #[default]
    Http,
    /// Long-lived xAI Responses WebSocket transport.
    WebSocket,
}

/// Bounds checked before an xAI request is parsed or forwarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XaiRestLimits {
    /// Maximum serialized JSON request size.
    pub max_body_bytes: usize,
    /// Maximum number of tools accepted by xAI Responses and Chat endpoints.
    pub max_tools: usize,
    /// Maximum number of Chat stop sequences.
    pub max_stop_sequences: usize,
}

impl Default for XaiRestLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 8 * 1024 * 1024,
            max_tools: 128,
            max_stop_sequences: 4,
        }
    }
}

/// A validated xAI JSON request and its explicit compatibility accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedXaiRestRequest {
    /// Upstream JSON bytes. Unchanged HTTP requests retain their exact input
    /// representation; only applied compatibility transforms reserialize.
    pub body: Vec<u8>,
    /// xAI compatibility rules and losses applied to the request.
    pub report: ConversionReport,
}

/// An xAI Chat request represented by Pooler's semantic request model.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedXaiChatRequest {
    /// Protocol-neutral request.
    pub request: SemanticRequest,
    /// Validated xAI JSON, including supported provider fields.
    pub body: Vec<u8>,
    /// Combined OpenAI Chat and xAI compatibility accounting.
    pub report: ConversionReport,
}

/// Errors raised while validating or adapting an xAI REST request.
#[derive(Debug, Error)]
pub enum XaiRestError {
    /// The request exceeded the configured parser bound.
    #[error("xAI request is too large: {observed} bytes exceeds limit {limit}")]
    BodyTooLarge {
        /// Serialized request size.
        observed: usize,
        /// Configured request limit.
        limit: usize,
    },
    /// The request was not valid JSON.
    #[error("invalid xAI request JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// The request JSON root was not an object.
    #[error("xAI request JSON must be an object")]
    RootNotObject,
    /// A required request field was absent.
    #[error("xAI request field `{0}` is missing")]
    MissingField(String),
    /// A request field had an invalid shape or value.
    #[error("invalid xAI request field `{field}`: {reason}")]
    InvalidField {
        /// Field path.
        field: String,
        /// Safe shape or value explanation.
        reason: &'static str,
    },
    /// Two request fields requested incompatible behavior.
    #[error("xAI request fields `{first}` and `{second}` cannot be used together")]
    ConflictingFields {
        /// First conflicting field.
        first: &'static str,
        /// Second conflicting field.
        second: &'static str,
    },
    /// The selected loss policy rejected an xAI compatibility difference.
    #[error("xAI request conversion rejected: {0}")]
    Conversion(#[from] ConversionError),
    /// The shared OpenAI Chat semantic codec rejected the request.
    #[error("invalid xAI Chat request: {0}")]
    OpenAiChat(#[from] OpenAiChatError),
}

/// Stateless, bounded xAI REST adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct XaiRestAdapter {
    limits: XaiRestLimits,
}

impl XaiRestAdapter {
    /// Creates an adapter with explicit request bounds.
    #[must_use]
    pub const fn new(limits: XaiRestLimits) -> Self {
        Self { limits }
    }

    /// Validates and prepares one xAI JSON request.
    pub fn prepare_request(
        &self,
        endpoint: XaiRestEndpoint,
        transport: XaiRestTransport,
        body: &[u8],
        policy: LossPolicy,
    ) -> Result<PreparedXaiRestRequest, XaiRestError> {
        let mut object = self.parse_object(body)?;
        let original = object.clone();
        let mut report = ConversionReport::default();
        match endpoint {
            XaiRestEndpoint::ChatCompletions => {
                if transport == XaiRestTransport::WebSocket {
                    return Err(invalid_field(
                        "transport",
                        "Chat Completions does not use xAI Responses WebSocket mode",
                    ));
                }
                self.prepare_chat(&mut object, policy, &mut report)?;
            }
            XaiRestEndpoint::Responses => {
                self.prepare_responses(&mut object, transport, policy, &mut report)?;
            }
            XaiRestEndpoint::ResponsesCompact => {
                if transport == XaiRestTransport::WebSocket {
                    return Err(invalid_field(
                        "transport",
                        "Responses compaction is available over HTTP only",
                    ));
                }
                self.prepare_compaction(&object)?;
            }
        }
        report.validate(policy)?;
        let body = if object == original {
            body.to_vec()
        } else {
            serde_json::to_vec(&Value::Object(object))?
        };
        Ok(PreparedXaiRestRequest { body, report })
    }

    /// Decodes xAI Chat JSON through the shared OpenAI-compatible semantic
    /// codec after applying provider-specific validation.
    pub fn decode_chat_request(
        &self,
        body: &[u8],
        policy: LossPolicy,
    ) -> Result<DecodedXaiChatRequest, XaiRestError> {
        let prepared = self.prepare_request(
            XaiRestEndpoint::ChatCompletions,
            XaiRestTransport::Http,
            body,
            policy,
        )?;
        let decoded = OpenAiChatCodec::decode_request_with_report(&prepared.body)?;
        let (request, mut report) = decoded.into_parts();
        report.merge(prepared.report);
        report.validate(policy)?;
        Ok(DecodedXaiChatRequest {
            request,
            body: prepared.body,
            report,
        })
    }

    /// Encodes a semantic request as xAI Chat JSON and checks xAI-specific
    /// request constraints.
    pub fn encode_chat_request(
        &self,
        request: &SemanticRequest,
        policy: LossPolicy,
    ) -> Result<PreparedXaiRestRequest, XaiRestError> {
        let encoded = OpenAiChatCodec::encode_request(request, policy)?;
        let prepared = self.prepare_request(
            XaiRestEndpoint::ChatCompletions,
            XaiRestTransport::Http,
            &encoded.body,
            policy,
        )?;
        let mut report = encoded.report;
        report.merge(prepared.report);
        report.validate(policy)?;
        Ok(PreparedXaiRestRequest {
            body: prepared.body,
            report,
        })
    }

    fn parse_object(&self, body: &[u8]) -> Result<Map<String, Value>, XaiRestError> {
        if body.len() > self.limits.max_body_bytes {
            return Err(XaiRestError::BodyTooLarge {
                observed: body.len(),
                limit: self.limits.max_body_bytes,
            });
        }
        serde_json::from_slice::<Value>(body)?
            .as_object()
            .cloned()
            .ok_or(XaiRestError::RootNotObject)
    }

    fn prepare_chat(
        &self,
        object: &mut Map<String, Value>,
        policy: LossPolicy,
        report: &mut ConversionReport,
    ) -> Result<(), XaiRestError> {
        require_nonempty_string(object, "model")?;
        require_array(object, "messages")?;
        validate_tools(object, self.limits.max_tools)?;
        validate_stop(object, self.limits.max_stop_sequences)?;
        validate_top_logprobs(object)?;
        validate_service_tier(object)?;
        validate_reasoning_effort(object, "reasoning_effort")?;
        validate_optional_nonempty_string(object, "prompt_cache_key")?;
        validate_search_parameters(object)?;
        validate_optional_object(object, "web_search_options")?;
        let deferred = optional_bool(object, "deferred")?.unwrap_or(false);
        let streaming = optional_bool(object, "stream")?.unwrap_or(false);
        if deferred && streaming {
            return Err(XaiRestError::ConflictingFields {
                first: "deferred",
                second: "stream",
            });
        }
        if object.get("search_parameters").is_some() {
            report.preserve_capability("xai.search_parameters");
        }
        if deferred {
            report.preserve_capability("xai.deferred_chat");
        }
        degrade_logit_bias(object, policy, report)?;
        Ok(())
    }

    fn prepare_responses(
        &self,
        object: &mut Map<String, Value>,
        transport: XaiRestTransport,
        policy: LossPolicy,
        report: &mut ConversionReport,
    ) -> Result<(), XaiRestError> {
        require_nonempty_string(object, "model")?;
        require_input(object)?;
        validate_tools(object, self.limits.max_tools)?;
        validate_top_logprobs(object)?;
        validate_service_tier(object)?;
        validate_optional_nonempty_string(object, "prompt_cache_key")?;
        validate_optional_nonempty_string(object, "previous_response_id")?;
        validate_optional_nonempty_string(object, "user")?;
        validate_search_parameters(object)?;
        validate_responses_reasoning(object, policy, report)?;
        validate_background(object, report)?;
        degrade_ignored_number_field(
            object,
            "frequency_penalty",
            "xAI Responses does not apply frequency_penalty",
            policy,
            report,
        )?;
        degrade_ignored_number_field(
            object,
            "presence_penalty",
            "xAI Responses does not apply presence_penalty",
            policy,
            report,
        )?;
        degrade_metadata(object, policy, report)?;
        degrade_truncation(object, policy, report)?;
        account_search_override(object, report);
        match transport {
            XaiRestTransport::Http => validate_http_responses_fields(object),
            XaiRestTransport::WebSocket => prepare_websocket_fields(object, report),
        }
    }

    fn prepare_compaction(&self, object: &Map<String, Value>) -> Result<(), XaiRestError> {
        require_nonempty_string(object, "model")?;
        require_input(object)?;
        Ok(())
    }
}

fn invalid_field(field: impl Into<String>, reason: &'static str) -> XaiRestError {
    XaiRestError::InvalidField {
        field: field.into(),
        reason,
    }
}

fn require_nonempty_string(object: &Map<String, Value>, field: &str) -> Result<(), XaiRestError> {
    let value = object
        .get(field)
        .ok_or_else(|| XaiRestError::MissingField(field.to_owned()))?;
    if value.as_str().is_some_and(|value| !value.trim().is_empty()) {
        Ok(())
    } else {
        Err(invalid_field(field, "must be a non-empty string"))
    }
}

fn validate_optional_nonempty_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<(), XaiRestError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(()),
        Some(_) => Err(invalid_field(field, "must be a non-empty string or null")),
    }
}

fn require_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Vec<Value>, XaiRestError> {
    object
        .get(field)
        .ok_or_else(|| XaiRestError::MissingField(field.to_owned()))?
        .as_array()
        .ok_or_else(|| invalid_field(field, "must be an array"))
}

fn require_input(object: &Map<String, Value>) -> Result<(), XaiRestError> {
    let value = object
        .get("input")
        .ok_or_else(|| XaiRestError::MissingField("input".to_owned()))?;
    if value.is_string() || value.is_array() {
        Ok(())
    } else {
        Err(invalid_field("input", "must be a string or an array"))
    }
}

fn optional_bool(object: &Map<String, Value>, field: &str) -> Result<Option<bool>, XaiRestError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_field(field, "must be a boolean or null")),
    }
}

fn validate_tools(object: &Map<String, Value>, limit: usize) -> Result<(), XaiRestError> {
    let Some(value) = object.get("tools") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let tools = value
        .as_array()
        .ok_or_else(|| invalid_field("tools", "must be an array or null"))?;
    if tools.len() > limit {
        return Err(invalid_field("tools", "exceeds xAI's 128-tool limit"));
    }
    Ok(())
}

fn validate_stop(object: &Map<String, Value>, limit: usize) -> Result<(), XaiRestError> {
    let Some(value) = object.get("stop") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let stop = value
        .as_array()
        .ok_or_else(|| invalid_field("stop", "must be an array or null"))?;
    if stop.len() > limit {
        return Err(invalid_field("stop", "exceeds xAI's four-sequence limit"));
    }
    if stop.iter().all(Value::is_string) {
        Ok(())
    } else {
        Err(invalid_field("stop", "entries must be strings"))
    }
}

fn validate_top_logprobs(object: &Map<String, Value>) -> Result<(), XaiRestError> {
    let Some(value) = object.get("top_logprobs") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let count = value
        .as_u64()
        .ok_or_else(|| invalid_field("top_logprobs", "must be an integer from 0 through 8"))?;
    if count > 8 {
        return Err(invalid_field(
            "top_logprobs",
            "must be an integer from 0 through 8",
        ));
    }
    if optional_bool(object, "logprobs")? != Some(true) {
        return Err(invalid_field(
            "top_logprobs",
            "requires logprobs to be true",
        ));
    }
    Ok(())
}

fn validate_service_tier(object: &Map<String, Value>) -> Result<(), XaiRestError> {
    match object.get("service_tier") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(value)) if matches!(value.as_str(), "default" | "priority") => Ok(()),
        Some(_) => Err(invalid_field(
            "service_tier",
            "must be default, priority, or null",
        )),
    }
}

fn validate_reasoning_effort(object: &Map<String, Value>, field: &str) -> Result<(), XaiRestError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(value))
            if matches!(value.as_str(), "none" | "low" | "medium" | "high") =>
        {
            Ok(())
        }
        Some(_) => Err(invalid_field(
            field,
            "must be none, low, medium, high, or null",
        )),
    }
}

fn validate_search_parameters(object: &Map<String, Value>) -> Result<(), XaiRestError> {
    let Some(value) = object.get("search_parameters") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let search = value
        .as_object()
        .ok_or_else(|| invalid_field("search_parameters", "must be an object or null"))?;
    match search.get("mode") {
        None | Some(Value::Null) => {}
        Some(Value::String(value)) if matches!(value.as_str(), "off" | "on" | "auto") => {}
        Some(_) => {
            return Err(invalid_field(
                "search_parameters.mode",
                "must be off, on, auto, or null",
            ));
        }
    }
    for field in ["from_date", "to_date"] {
        if let Some(value) = search.get(field) {
            if !value.is_null() && !value.as_str().is_some_and(looks_like_iso_date) {
                return Err(invalid_field(
                    format!("search_parameters.{field}"),
                    "must use YYYY-MM-DD",
                ));
            }
        }
    }
    match search.get("max_search_results") {
        None | Some(Value::Null) | Some(Value::Number(_)) => {}
        Some(_) => {
            return Err(invalid_field(
                "search_parameters.max_search_results",
                "must be an unsigned integer or null",
            ));
        }
    }
    if search
        .get("max_search_results")
        .is_some_and(|value| !value.is_null() && value.as_u64().is_none())
    {
        return Err(invalid_field(
            "search_parameters.max_search_results",
            "must be an unsigned integer or null",
        ));
    }
    match search.get("return_citations") {
        None | Some(Value::Null | Value::Bool(_)) => {}
        Some(_) => {
            return Err(invalid_field(
                "search_parameters.return_citations",
                "must be a boolean or null",
            ));
        }
    }
    match search.get("sources") {
        None | Some(Value::Null | Value::Array(_)) => Ok(()),
        Some(_) => Err(invalid_field(
            "search_parameters.sources",
            "must be an array or null",
        )),
    }
}

fn looks_like_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn validate_optional_object(object: &Map<String, Value>, field: &str) -> Result<(), XaiRestError> {
    match object.get(field) {
        None | Some(Value::Null | Value::Object(_)) => Ok(()),
        Some(_) => Err(invalid_field(field, "must be an object or null")),
    }
}

fn validate_responses_reasoning(
    object: &mut Map<String, Value>,
    policy: LossPolicy,
    report: &mut ConversionReport,
) -> Result<(), XaiRestError> {
    validate_optional_object(object, "reasoning")?;
    validate_reasoning_effort(object, "reasoning_effort")?;
    let has_reasoning = object
        .get("reasoning")
        .is_some_and(|value| !value.is_null());
    let has_alternative = object
        .get("reasoning_effort")
        .is_some_and(|value| !value.is_null());
    if has_reasoning && has_alternative {
        report.drop_optional(
            "reasoning_effort",
            "xAI ignores reasoning_effort when reasoning is present",
        );
        if policy == LossPolicy::Degrade {
            object.remove("reasoning_effort");
        }
    }
    Ok(())
}

fn validate_background(
    object: &Map<String, Value>,
    report: &mut ConversionReport,
) -> Result<(), XaiRestError> {
    if optional_bool(object, "background")? == Some(true) {
        report.unsupported_required(
            "background",
            "xAI Responses does not support asynchronous background execution",
        );
    }
    Ok(())
}

fn degrade_logit_bias(
    object: &mut Map<String, Value>,
    policy: LossPolicy,
    report: &mut ConversionReport,
) -> Result<(), XaiRestError> {
    let Some(value) = object.get("logit_bias") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let bias = value
        .as_object()
        .ok_or_else(|| invalid_field("logit_bias", "must be an object or null"))?;
    if bias.is_empty() {
        report.apply_rule("xai.chat.empty_logit_bias_is_noop");
    } else {
        report.degrade_field("logit_bias", "xAI documents logit_bias as unsupported");
        if policy == LossPolicy::Degrade {
            object.remove("logit_bias");
        }
    }
    Ok(())
}

fn degrade_ignored_number_field(
    object: &mut Map<String, Value>,
    field: &'static str,
    reason: &'static str,
    policy: LossPolicy,
    report: &mut ConversionReport,
) -> Result<(), XaiRestError> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let value = value
        .as_f64()
        .ok_or_else(|| invalid_field(field, "must be a number or null"))?;
    if value == 0.0 {
        report.apply_rule(format!("xai.responses.{field}_zero_is_noop"));
    } else {
        report.degrade_field(field, reason);
        if policy == LossPolicy::Degrade {
            object.remove(field);
        }
    }
    Ok(())
}

fn degrade_metadata(
    object: &mut Map<String, Value>,
    policy: LossPolicy,
    report: &mut ConversionReport,
) -> Result<(), XaiRestError> {
    let Some(value) = object.get("metadata") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let metadata = value
        .as_object()
        .ok_or_else(|| invalid_field("metadata", "must be an object"))?;
    if !metadata.is_empty() {
        report.degrade_field(
            "metadata",
            "xAI retains metadata only for wire compatibility",
        );
        if policy == LossPolicy::Degrade {
            object.remove("metadata");
        }
    }
    Ok(())
}

fn degrade_truncation(
    object: &mut Map<String, Value>,
    policy: LossPolicy,
    report: &mut ConversionReport,
) -> Result<(), XaiRestError> {
    let Some(value) = object.get("truncation") else {
        return Ok(());
    };
    match value {
        Value::Null => Ok(()),
        Value::String(value) if value == "disabled" => {
            report.apply_rule("xai.responses.truncation_disabled_compatibility");
            Ok(())
        }
        Value::String(_) => {
            report.degrade_field(
                "truncation",
                "xAI Responses accepts but does not apply truncation strategies",
            );
            if policy == LossPolicy::Degrade {
                object.remove("truncation");
            }
            Ok(())
        }
        _ => Err(invalid_field("truncation", "must be a string or null")),
    }
}

fn account_search_override(object: &Map<String, Value>, report: &mut ConversionReport) {
    if object.get("search_parameters").is_none() {
        return;
    }
    let has_preview_tool = object
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|tool| tool.get("type").and_then(Value::as_str) == Some("web_search_preview"))
        });
    if has_preview_tool {
        report.apply_rule("xai.search_parameters_overrides_web_search_preview");
    }
}

fn validate_http_responses_fields(object: &mut Map<String, Value>) -> Result<(), XaiRestError> {
    if object.contains_key("generate") {
        return Err(invalid_field(
            "generate",
            "is available only in xAI Responses WebSocket mode",
        ));
    }
    if object.contains_key("type") {
        return Err(invalid_field(
            "type",
            "response.create is a WebSocket envelope field",
        ));
    }
    optional_bool(object, "stream")?;
    Ok(())
}

fn prepare_websocket_fields(
    object: &mut Map<String, Value>,
    report: &mut ConversionReport,
) -> Result<(), XaiRestError> {
    if let Some(value) = object.get("type") {
        if value.as_str() != Some("response.create") {
            return Err(invalid_field("type", "must be response.create"));
        }
    }
    optional_bool(object, "generate")?;
    if object.remove("stream").is_some() {
        report.apply_rule("xai.websocket.responses_always_stream");
    }
    if object.remove("background").is_some() {
        report.apply_rule("xai.websocket.omit_background");
    }
    object.insert(
        "type".to_owned(),
        Value::String("response.create".to_owned()),
    );
    report.preserve_capability("xai.responses.websocket");
    Ok(())
}

#[cfg(test)]
mod tests {
    use pooler_protocol::{LossPolicy, Role};
    use serde_json::{json, Value};

    use super::{XaiRestAdapter, XaiRestEndpoint, XaiRestError, XaiRestLimits, XaiRestTransport};

    #[test]
    fn rejects_unsupported_chat_field_under_strict_policy() {
        let body = br#"{"model":"grok","messages":[],"logit_bias":{"1":2}}"#;
        let error = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::ChatCompletions,
                XaiRestTransport::Http,
                body,
                LossPolicy::Reject,
            )
            .expect_err("unsupported field must be explicit");
        assert!(matches!(error, XaiRestError::Conversion(_)));
    }

    #[test]
    fn degrading_chat_request_removes_unsupported_field() {
        let body = br#"{"model":"grok","messages":[],"logit_bias":{"1":2}}"#;
        let prepared = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::ChatCompletions,
                XaiRestTransport::Http,
                body,
                LossPolicy::Degrade,
            )
            .expect("degraded request");
        let value: Value = serde_json::from_slice(&prepared.body).expect("JSON");
        assert!(value.get("logit_bias").is_none());
        assert_eq!(prepared.report.degraded_fields, ["logit_bias"]);
    }

    #[test]
    fn websocket_request_uses_response_create_envelope() {
        let body = br#"{"model":"grok","input":"hello","stream":false,"background":false,"generate":false}"#;
        let prepared = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::Responses,
                XaiRestTransport::WebSocket,
                body,
                LossPolicy::Reject,
            )
            .expect("WebSocket request");
        let value: Value = serde_json::from_slice(&prepared.body).expect("JSON");
        assert_eq!(value["type"], "response.create");
        assert_eq!(value["generate"], false);
        assert!(value.get("stream").is_none());
        assert!(value.get("background").is_none());
    }

    #[test]
    fn background_execution_is_never_silently_degraded() {
        let body = br#"{"model":"grok","input":"hello","background":true}"#;
        let error = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::Responses,
                XaiRestTransport::Http,
                body,
                LossPolicy::Degrade,
            )
            .expect_err("background semantics are required");
        assert!(matches!(error, XaiRestError::Conversion(_)));
    }

    #[test]
    fn zero_responses_penalties_are_accepted_as_noops() {
        let body = br#"{
          "model":"grok",
          "input":"hello",
          "frequency_penalty":0,
          "presence_penalty":0.0
        }"#;
        let prepared = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::Responses,
                XaiRestTransport::Http,
                body,
                LossPolicy::Reject,
            )
            .expect("zero penalties have no semantic effect");
        assert!(prepared.report.is_lossless());
        assert_eq!(prepared.report.rules_applied.len(), 2);
    }

    #[test]
    fn validates_xai_tool_limit_before_forwarding() {
        let tools = (0..129)
            .map(|index| json!({"type":"function","name":format!("tool-{index}")}))
            .collect::<Vec<_>>();
        let body = serde_json::to_vec(&json!({
            "model":"grok",
            "input":"hello",
            "tools":tools
        }))
        .expect("JSON");
        let error = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::Responses,
                XaiRestTransport::Http,
                &body,
                LossPolicy::Reject,
            )
            .expect_err("tool bound");
        assert!(matches!(
            error,
            XaiRestError::InvalidField { ref field, .. } if field == "tools"
        ));
    }

    #[test]
    fn semantic_chat_wrapper_keeps_xai_search_fields() {
        let body = br#"{
          "model":"grok-4.6",
          "messages":[{"role":"user","content":"latest news"}],
          "search_parameters":{"mode":"auto","return_citations":true},
          "prompt_cache_key":"conversation-a"
        }"#;
        let decoded = XaiRestAdapter::default()
            .decode_chat_request(body, LossPolicy::Reject)
            .expect("xAI Chat request");
        assert_eq!(decoded.request.model, "grok-4.6");
        assert_eq!(
            decoded.request.messages().next().expect("message").role,
            Role::User
        );
        let value: Value = serde_json::from_slice(&decoded.body).expect("JSON");
        assert_eq!(value["search_parameters"]["mode"], "auto");
        assert!(decoded
            .report
            .preserved_capabilities
            .iter()
            .any(|capability| capability == "xai.search_parameters"));
    }

    #[test]
    fn responses_compact_requires_input_and_preserves_valid_json() {
        let body = b"{ \n  \"model\": \"grok\", \"input\": \"sanitized\" \n}";
        let prepared = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::ResponsesCompact,
                XaiRestTransport::Http,
                body,
                LossPolicy::Reject,
            )
            .expect("valid Responses Compact request");
        assert_eq!(prepared.body, body);

        let error = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::ResponsesCompact,
                XaiRestTransport::Http,
                br#"{"model":"grok"}"#,
                LossPolicy::Reject,
            )
            .expect_err("xAI Compact input is required");
        assert!(matches!(
            error,
            XaiRestError::MissingField(ref field) if field == "input"
        ));
    }

    #[test]
    fn responses_compact_rejects_websocket_transport() {
        let error = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::ResponsesCompact,
                XaiRestTransport::WebSocket,
                br#"{"model":"grok","input":"sanitized"}"#,
                LossPolicy::Reject,
            )
            .expect_err("Responses Compact is HTTP-only");
        assert!(matches!(
            error,
            XaiRestError::InvalidField { ref field, .. } if field == "transport"
        ));
    }

    #[test]
    fn unchanged_http_request_keeps_exact_json_bytes() {
        let body = b"{ \n  \"model\": \"grok\", \"input\": \"hello\" \n}";
        let prepared = XaiRestAdapter::default()
            .prepare_request(
                XaiRestEndpoint::Responses,
                XaiRestTransport::Http,
                body,
                LossPolicy::Reject,
            )
            .expect("valid request");
        assert_eq!(prepared.body, body);
    }

    #[test]
    fn request_body_limit_is_checked_before_json_parsing() {
        let adapter = XaiRestAdapter::new(XaiRestLimits {
            max_body_bytes: 4,
            ..XaiRestLimits::default()
        });
        let error = adapter
            .prepare_request(
                XaiRestEndpoint::Responses,
                XaiRestTransport::Http,
                b"not-json",
                LossPolicy::Reject,
            )
            .expect_err("body limit");
        assert!(matches!(error, XaiRestError::BodyTooLarge { .. }));
    }
}
