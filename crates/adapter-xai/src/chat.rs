use std::collections::BTreeMap;

use pooler_protocol::{
    ConversionReport, EncodedChatChunk, FinishReason, LossPolicy, OpenAiChatError,
    OpenAiChatEventDecoder, OpenAiChatEventEncoder, StreamEvent, StreamEventKind, Usage,
};
use serde_json::{Map, Value};

/// Semantic opaque-event media type used for xAI Chat citations.
pub const XAI_CHAT_CITATIONS_MEDIA_TYPE: &str = "application/vnd.xai.chat.citations+json";
/// Semantic opaque-event media type used for xAI Chat output files.
pub const XAI_CHAT_OUTPUT_FILES_MEDIA_TYPE: &str = "application/vnd.xai.chat.output-files+json";

const DEFAULT_RESPONSE_ID: &str = "pooler-response";

/// Stateful decoder for xAI's OpenAI-compatible Chat stream.
///
/// The shared Chat decoder handles standard text, reasoning, tools, usage, and
/// completion state. This wrapper adds xAI usage counters, citations, output
/// files, service tier, and the xAI `end_turn` finish spelling without hiding
/// those provider differences.
#[derive(Clone, Debug, Default)]
pub struct XaiChatEventDecoder {
    inner: OpenAiChatEventDecoder,
    next_sequence: u64,
    last_citations: Option<Vec<u8>>,
    last_output_files: Option<Vec<u8>>,
    service_tier: Option<String>,
}

impl XaiChatEventDecoder {
    /// Creates an empty decoder for one xAI Chat stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes one Chat Completions JSON chunk.
    pub fn decode_chunk(&mut self, input: &[u8]) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        let value: Value = serde_json::from_slice(input)?;
        let object = value
            .as_object()
            .ok_or_else(|| OpenAiChatError::InvalidShape {
                field: "chunk".to_owned(),
                expected: "an object",
            })?;
        let mut events = self.inner.decode_chunk(input)?;
        enrich_usage_events(&mut events, object)?;
        normalize_finish_reason(&mut events);
        let extra = self.decode_xai_fields(object)?;
        insert_before_terminal(&mut events, extra);
        self.resequence(&mut events);
        Ok(events)
    }

    /// Decodes an SSE data payload, including the `[DONE]` sentinel.
    pub fn decode_data(&mut self, data: &[u8]) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        if data == b"[DONE]" {
            let mut events = self.inner.decode_data(data)?;
            normalize_finish_reason(&mut events);
            self.resequence(&mut events);
            return Ok(events);
        }
        self.decode_chunk(data)
    }

    /// Finishes a stream after its final JSON chunk.
    pub fn finish(&mut self) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        let mut events = self.inner.finish()?;
        normalize_finish_reason(&mut events);
        self.resequence(&mut events);
        Ok(events)
    }

    fn decode_xai_fields(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEventKind>, OpenAiChatError> {
        let mut events = Vec::new();
        if let Some(tier) = object.get("service_tier").filter(|value| !value.is_null()) {
            let tier = tier.as_str().ok_or_else(|| OpenAiChatError::InvalidShape {
                field: "service_tier".to_owned(),
                expected: "a string or null",
            })?;
            if self.service_tier.as_deref() != Some(tier) {
                self.service_tier = Some(tier.to_owned());
                events.push(StreamEventKind::Metadata {
                    values: BTreeMap::from([("service_tier".to_owned(), tier.to_owned())]),
                });
            }
        }
        append_changed_json(
            object,
            "citations",
            XAI_CHAT_CITATIONS_MEDIA_TYPE,
            &mut self.last_citations,
            &mut events,
        )?;
        append_changed_json(
            object,
            "output_files",
            XAI_CHAT_OUTPUT_FILES_MEDIA_TYPE,
            &mut self.last_output_files,
            &mut events,
        )?;
        Ok(events)
    }

    fn resequence(&mut self, events: &mut [StreamEvent]) {
        for event in events {
            self.next_sequence = self.next_sequence.saturating_add(1);
            event.sequence = self.next_sequence;
        }
    }
}

/// Stateful encoder for xAI's OpenAI-compatible Chat stream.
///
/// Standard Chat events are delegated to Pooler's shared encoder. xAI's
/// reasoning deltas, citations, output files, service tier, fingerprint, and
/// extended usage counters are restored at this provider boundary so a
/// same-wire semantic route remains lossless.
#[derive(Clone, Debug)]
pub struct XaiChatEventEncoder {
    inner: OpenAiChatEventEncoder,
    response_id: String,
    model: String,
    completed: bool,
}

impl Default for XaiChatEventEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl XaiChatEventEncoder {
    /// Creates an encoder with deterministic fallback response metadata.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OpenAiChatEventEncoder::new(),
            response_id: DEFAULT_RESPONSE_ID.to_owned(),
            model: String::new(),
            completed: false,
        }
    }

    /// Encodes one semantic event into an xAI Chat JSON chunk.
    pub fn encode_event(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<Option<EncodedChatChunk>, OpenAiChatError> {
        if self.completed {
            return Err(OpenAiChatError::UnsupportedEvent {
                message: "event appeared after completion".to_owned(),
            });
        }
        match &event.kind {
            StreamEventKind::ResponseStart { response_id, model } => {
                if let Some(response_id) = response_id {
                    self.response_id.clone_from(response_id);
                }
                if let Some(model) = model {
                    self.model.clone_from(model);
                }
                self.inner.encode_event(event, policy)
            }
            StreamEventKind::ReasoningStart | StreamEventKind::ReasoningEnd { .. } => Ok(None),
            StreamEventKind::ReasoningDelta { text } => {
                let mut chunk = self.base_chunk();
                chunk["choices"] = serde_json::json!([{
                    "index": 0,
                    "delta": {"reasoning_content": text},
                    "finish_reason": null
                }]);
                self.encoded_chunk(chunk, ConversionReport::default(), policy)
                    .map(Some)
            }
            StreamEventKind::Metadata { values } => self.encode_metadata(values, policy).map(Some),
            StreamEventKind::Opaque { media_type, data }
                if matches!(
                    media_type.as_str(),
                    XAI_CHAT_CITATIONS_MEDIA_TYPE | XAI_CHAT_OUTPUT_FILES_MEDIA_TYPE
                ) =>
            {
                self.encode_xai_json(media_type, data, policy).map(Some)
            }
            StreamEventKind::Opaque { .. } => {
                let mut report = ConversionReport::default();
                report.unsupported_required(
                    "opaque_event",
                    "the opaque event is not an xAI Chat citations or output-files payload",
                );
                self.encoded_chunk(self.base_chunk(), report, policy)
                    .map(Some)
            }
            StreamEventKind::Usage { usage } => {
                let encoded = self.inner.encode_event(event, policy)?;
                encoded
                    .map(|chunk| enrich_encoded_usage(chunk, usage))
                    .transpose()
            }
            StreamEventKind::Completion { usage, .. } => {
                let encoded = self.inner.encode_event(event, policy)?;
                self.completed = true;
                encoded
                    .map(|chunk| match usage {
                        Some(usage) => enrich_encoded_usage(chunk, usage),
                        None => Ok(chunk),
                    })
                    .transpose()
            }
            StreamEventKind::Failure { .. } => {
                let encoded = self.inner.encode_event(event, policy)?;
                self.completed = true;
                Ok(encoded)
            }
            _ => self.inner.encode_event(event, policy),
        }
    }

    fn encode_metadata(
        &self,
        values: &BTreeMap<String, String>,
        policy: LossPolicy,
    ) -> Result<EncodedChatChunk, OpenAiChatError> {
        let mut chunk = self.base_chunk();
        let mut report = ConversionReport::default();
        for (key, value) in values {
            match key.as_str() {
                "service_tier" | "system_fingerprint" => {
                    chunk[key] = Value::String(value.clone());
                    report.preserve_capability(format!("xai.chat.{key}"));
                }
                _ => report.drop_optional(
                    format!("metadata.{key}"),
                    "xAI Chat has no documented field for this semantic metadata value",
                ),
            }
        }
        self.encoded_chunk(chunk, report, policy)
    }

    fn encode_xai_json(
        &self,
        media_type: &str,
        data: &[u8],
        policy: LossPolicy,
    ) -> Result<EncodedChatChunk, OpenAiChatError> {
        let field = match media_type {
            XAI_CHAT_CITATIONS_MEDIA_TYPE => "citations",
            XAI_CHAT_OUTPUT_FILES_MEDIA_TYPE => "output_files",
            _ => unreachable!("caller validates xAI Chat media type"),
        };
        let value: Value = serde_json::from_slice(data)?;
        if !value.is_array() {
            return Err(OpenAiChatError::InvalidShape {
                field: field.to_owned(),
                expected: "an array",
            });
        }
        let mut chunk = self.base_chunk();
        chunk[field] = value;
        let mut report = ConversionReport::default();
        report.preserve_capability(format!("xai.chat.{field}"));
        self.encoded_chunk(chunk, report, policy)
    }

    fn encoded_chunk(
        &self,
        value: Value,
        report: ConversionReport,
        policy: LossPolicy,
    ) -> Result<EncodedChatChunk, OpenAiChatError> {
        report.validate(policy)?;
        Ok(EncodedChatChunk {
            body: serde_json::to_vec(&value)?,
            report,
        })
    }

    fn base_chunk(&self) -> Value {
        serde_json::json!({
            "id": self.response_id,
            "object": "chat.completion.chunk",
            "created": 0,
            "model": self.model,
            "choices": []
        })
    }
}

fn enrich_encoded_usage(
    mut chunk: EncodedChatChunk,
    usage: &Usage,
) -> Result<EncodedChatChunk, OpenAiChatError> {
    let mut value: Value = serde_json::from_slice(&chunk.body)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "chunk".to_owned(),
            expected: "an object",
        })?;
    let Some(encoded_usage) = object.get_mut("usage").and_then(Value::as_object_mut) else {
        return Ok(chunk);
    };
    copy_usage_detail(usage, "cost_in_usd_ticks", encoded_usage, None);
    copy_usage_detail(usage, "num_sources_used", encoded_usage, None);
    for (source, destination) in [
        ("prompt_text_tokens", "text_tokens"),
        ("prompt_audio_tokens", "audio_tokens"),
        ("prompt_image_tokens", "image_tokens"),
    ] {
        copy_usage_detail(
            usage,
            source,
            encoded_usage,
            Some(("prompt_tokens_details", destination)),
        );
    }
    for (source, destination) in [
        ("completion_audio_tokens", "audio_tokens"),
        ("accepted_prediction_tokens", "accepted_prediction_tokens"),
        ("rejected_prediction_tokens", "rejected_prediction_tokens"),
    ] {
        copy_usage_detail(
            usage,
            source,
            encoded_usage,
            Some(("completion_tokens_details", destination)),
        );
    }
    chunk.body = serde_json::to_vec(&value)?;
    Ok(chunk)
}

fn copy_usage_detail(
    usage: &Usage,
    source: &str,
    destination: &mut Map<String, Value>,
    nested: Option<(&str, &str)>,
) {
    let Some(value) = usage.details.get(source).copied() else {
        return;
    };
    if let Some((object, field)) = nested {
        let nested = destination
            .entry(object.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(nested) = nested.as_object_mut() {
            nested.insert(field.to_owned(), Value::from(value));
        }
    } else {
        destination.insert(source.to_owned(), Value::from(value));
    }
}

fn append_changed_json(
    object: &Map<String, Value>,
    field: &str,
    media_type: &str,
    previous: &mut Option<Vec<u8>>,
    events: &mut Vec<StreamEventKind>,
) -> Result<(), OpenAiChatError> {
    let Some(value) = object.get(field).filter(|value| !value.is_null()) else {
        return Ok(());
    };
    if !value.is_array() {
        return Err(OpenAiChatError::InvalidShape {
            field: field.to_owned(),
            expected: "an array or null",
        });
    }
    let bytes = serde_json::to_vec(value)?;
    if previous.as_deref() != Some(bytes.as_slice()) {
        *previous = Some(bytes.clone());
        events.push(StreamEventKind::Opaque {
            media_type: media_type.to_owned(),
            data: bytes,
        });
    }
    Ok(())
}

fn enrich_usage_events(
    events: &mut [StreamEvent],
    object: &Map<String, Value>,
) -> Result<(), OpenAiChatError> {
    let Some(usage) = object.get("usage").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let usage = usage
        .as_object()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "usage".to_owned(),
            expected: "an object",
        })?;
    for event in events {
        match &mut event.kind {
            StreamEventKind::Usage {
                usage: semantic_usage,
            }
            | StreamEventKind::Completion {
                usage: Some(semantic_usage),
                ..
            } => enrich_usage(semantic_usage, usage)?,
            _ => {}
        }
    }
    Ok(())
}

fn enrich_usage(usage: &mut Usage, object: &Map<String, Value>) -> Result<(), OpenAiChatError> {
    copy_usage_count(object, "cost_in_usd_ticks", usage)?;
    copy_usage_count(object, "num_sources_used", usage)?;
    if let Some(details) = optional_object(object, "prompt_tokens_details")? {
        copy_usage_count_as(details, "text_tokens", "prompt_text_tokens", usage)?;
        copy_usage_count_as(details, "audio_tokens", "prompt_audio_tokens", usage)?;
        copy_usage_count_as(details, "image_tokens", "prompt_image_tokens", usage)?;
    }
    if let Some(details) = optional_object(object, "completion_tokens_details")? {
        copy_usage_count_as(details, "audio_tokens", "completion_audio_tokens", usage)?;
        copy_usage_count(details, "accepted_prediction_tokens", usage)?;
        copy_usage_count(details, "rejected_prediction_tokens", usage)?;
    }
    Ok(())
}

fn optional_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a Map<String, Value>>, OpenAiChatError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(OpenAiChatError::InvalidShape {
            field: format!("usage.{field}"),
            expected: "an object or null",
        }),
    }
}

fn copy_usage_count(
    object: &Map<String, Value>,
    field: &str,
    usage: &mut Usage,
) -> Result<(), OpenAiChatError> {
    copy_usage_count_as(object, field, field, usage)
}

fn copy_usage_count_as(
    object: &Map<String, Value>,
    source_field: &str,
    destination_field: &str,
    usage: &mut Usage,
) -> Result<(), OpenAiChatError> {
    let Some(value) = object.get(source_field) else {
        return Ok(());
    };
    let value = value
        .as_u64()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: format!("usage.{source_field}"),
            expected: "an unsigned integer",
        })?;
    usage.details.insert(destination_field.to_owned(), value);
    Ok(())
}

fn normalize_finish_reason(events: &mut [StreamEvent]) {
    for event in events {
        if let StreamEventKind::Completion { finish_reason, .. } = &mut event.kind {
            if *finish_reason == FinishReason::Other("end_turn".to_owned()) {
                *finish_reason = FinishReason::Stop;
            }
        }
    }
}

fn insert_before_terminal(events: &mut Vec<StreamEvent>, extra: Vec<StreamEventKind>) {
    let terminal_index = events
        .iter()
        .position(|event| event.kind.is_terminal())
        .unwrap_or(events.len());
    for (offset, kind) in extra.into_iter().enumerate() {
        events.insert(terminal_index + offset, StreamEvent::new(0, kind));
    }
}

#[cfg(test)]
mod tests {
    use pooler_protocol::{FinishReason, StreamEventKind, StreamValidator};
    use serde_json::Value;

    use super::{XaiChatEventDecoder, XaiChatEventEncoder};

    #[test]
    fn preserves_xai_usage_and_citations_before_completion() {
        let mut decoder = XaiChatEventDecoder::new();
        let mut events = decoder
            .decode_chunk(
                br#"{
                  "id":"chat-1",
                  "model":"grok-4.6",
                  "service_tier":"priority",
                  "choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":"end_turn"}],
                  "citations":["https://example.test/source"],
                  "usage":{
                    "prompt_tokens":3,
                    "completion_tokens":1,
                    "total_tokens":4,
                    "cost_in_usd_ticks":12,
                    "num_sources_used":1,
                    "prompt_tokens_details":{"text_tokens":2,"audio_tokens":1,"image_tokens":0},
                    "completion_tokens_details":{"audio_tokens":0,"accepted_prediction_tokens":1,"rejected_prediction_tokens":0}
                  }
                }"#,
            )
            .expect("xAI chunk");
        events.extend(decoder.decode_data(b"[DONE]").expect("done"));
        let mut validator = StreamValidator::default();
        for event in &events {
            validator.accept(event).expect("valid event sequence");
        }
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::Opaque { media_type, .. }
                if media_type == "application/vnd.xai.chat.citations+json"
        )));
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::Stop,
                usage: Some(usage)
            } if usage.details.get("cost_in_usd_ticks") == Some(&12)
                && usage.details.get("prompt_audio_tokens") == Some(&1)
                && usage.details.get("completion_audio_tokens") == Some(&0)
        )));
    }

    #[test]
    fn same_wire_encoder_restores_xai_fields_without_loss() {
        let mut decoder = XaiChatEventDecoder::new();
        let events = decoder
            .decode_chunk(
                br#"{
                  "id":"chat-1",
                  "model":"grok-4.6",
                  "service_tier":"priority",
                  "choices":[{"index":0,"delta":{"reasoning_content":"think","content":"hello"},"finish_reason":"end_turn"}],
                  "citations":["https://example.test/source"],
                  "output_files":[{"id":"file-1"}],
                  "usage":{
                    "prompt_tokens":3,
                    "completion_tokens":1,
                    "total_tokens":4,
                    "cost_in_usd_ticks":12,
                    "num_sources_used":1,
                    "prompt_tokens_details":{"text_tokens":2,"audio_tokens":1,"image_tokens":0},
                    "completion_tokens_details":{"audio_tokens":0,"accepted_prediction_tokens":1,"rejected_prediction_tokens":0}
                  }
                }"#,
            )
            .expect("xAI chunk");
        let mut encoder = XaiChatEventEncoder::new();
        let chunks = events
            .iter()
            .filter_map(|event| {
                encoder
                    .encode_event(event, pooler_protocol::LossPolicy::Reject)
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("lossless xAI chunks");
        let values = chunks
            .iter()
            .map(|chunk| serde_json::from_slice::<Value>(&chunk.body).expect("chunk JSON"))
            .collect::<Vec<_>>();
        assert!(values
            .iter()
            .any(|value| { value["choices"][0]["delta"]["reasoning_content"] == "think" }));
        assert!(values
            .iter()
            .any(|value| value["service_tier"] == "priority"));
        assert!(values
            .iter()
            .any(|value| value["citations"][0] == "https://example.test/source"));
        assert!(values
            .iter()
            .any(|value| value["output_files"][0]["id"] == "file-1"));
        assert!(values
            .iter()
            .any(|value| value["usage"]["cost_in_usd_ticks"] == 12));
    }
}
