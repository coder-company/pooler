use std::collections::{BTreeMap, BTreeSet};

use pooler_protocol::{
    ConversionReport, FinishReason, LossPolicy, PreservedJson, PreservedJsonError, StreamError,
    StreamEvent, StreamEventKind, Usage,
};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{XaiRestAdapter, XaiRestEndpoint, XaiRestError, XaiRestTransport};

const REALTIME_EVENT_MEDIA_TYPE: &str = "application/vnd.xai.responses.event+json";

/// Bounds for xAI Responses WebSocket JSON messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XaiRealtimeLimits {
    /// Maximum encoded text-message size.
    pub max_message_bytes: usize,
    /// Maximum accumulated argument bytes for one function call.
    pub max_tool_arguments_bytes: usize,
}

impl Default for XaiRealtimeLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 8 * 1024 * 1024,
            max_tool_arguments_bytes: 1024 * 1024,
        }
    }
}

/// A client `response.create` WebSocket message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedXaiRealtimeRequest {
    /// UTF-8 JSON WebSocket text-message payload.
    pub body: Vec<u8>,
    /// Requested model.
    pub model: String,
    /// Previous response continued on this connection, when present.
    pub previous_response_id: Option<String>,
    /// Whether this turn generates output. `false` is an xAI warmup.
    pub generate: bool,
    /// Compatibility rules applied while creating the WebSocket envelope.
    pub report: ConversionReport,
}

/// Semantic classification of one xAI Responses WebSocket server event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XaiRealtimeEventKind {
    /// A response turn started.
    ResponseCreated,
    /// An output text block started.
    TextStarted,
    /// An output text fragment arrived.
    TextDelta,
    /// An output text block ended.
    TextDone,
    /// A reasoning block started.
    ReasoningStarted,
    /// A reasoning fragment arrived.
    ReasoningDelta,
    /// A reasoning block ended.
    ReasoningDone,
    /// A client-side function call started.
    ToolCallStarted,
    /// A function argument fragment arrived.
    ToolArgumentsDelta,
    /// A client-side function call ended.
    ToolCallDone,
    /// A response turn completed successfully.
    ResponseCompleted,
    /// A response turn ended unsuccessfully.
    ResponseFailed,
    /// xAI emitted a WebSocket error envelope.
    Error,
    /// A valid Responses event has no common semantic event shape.
    Other(String),
}

/// One decoded xAI server message.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedXaiRealtimeEvent {
    /// Original provider event type.
    pub event_type: String,
    /// Provider-aware event classification.
    pub kind: XaiRealtimeEventKind,
    /// Zero or more protocol-neutral events in valid lifecycle order.
    pub semantic_events: Vec<StreamEvent>,
    /// Exact JSON payload for native forwarding or later inspection.
    pub raw: PreservedJson,
}

/// Errors raised by xAI Responses WebSocket request and event codecs.
#[derive(Debug, Error)]
pub enum XaiRealtimeError {
    /// REST-to-WebSocket request preparation failed.
    #[error("invalid xAI realtime request: {0}")]
    Request(#[from] XaiRestError),
    /// A WebSocket text message exceeded the configured bound.
    #[error("xAI realtime message is too large: {observed} bytes exceeds limit {limit}")]
    MessageTooLarge {
        /// Message size.
        observed: usize,
        /// Configured message limit.
        limit: usize,
    },
    /// A WebSocket text message was not valid JSON.
    #[error("invalid xAI realtime JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// A parsed event could not be retained as exact JSON.
    #[error("unable to preserve xAI realtime JSON: {0}")]
    PreserveJson(#[from] PreservedJsonError),
    /// A JSON message root was not an object.
    #[error("xAI realtime JSON must be an object")]
    RootNotObject,
    /// A required event field was missing.
    #[error("xAI realtime field `{0}` is missing")]
    MissingField(String),
    /// An event field had the wrong JSON shape.
    #[error("invalid xAI realtime field `{field}`: {reason}")]
    InvalidField {
        /// Field path.
        field: String,
        /// Safe shape or value explanation.
        reason: &'static str,
    },
    /// A server event violated the documented response lifecycle.
    #[error("invalid xAI realtime event `{event_type}`: {reason}")]
    InvalidLifecycle {
        /// Event type that violated the lifecycle.
        event_type: String,
        /// Safe invariant explanation.
        reason: String,
    },
    /// A wire sequence number failed to increase.
    #[error("xAI realtime sequence {actual} is not greater than {previous}")]
    NonMonotonicSequence {
        /// Last accepted provider sequence.
        previous: u64,
        /// Rejected provider sequence.
        actual: u64,
    },
    /// Function arguments exceeded the configured accumulation bound.
    #[error("xAI realtime tool arguments exceed limit {limit}")]
    ToolArgumentsTooLarge {
        /// Configured argument limit.
        limit: usize,
    },
    /// The socket ended during an active response.
    #[error("xAI realtime socket ended before the active response became terminal")]
    IncompleteResponse,
}

/// Encoder for the client side of xAI Responses WebSocket mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct XaiRealtimeRequestCodec {
    rest: XaiRestAdapter,
}

impl XaiRealtimeRequestCodec {
    /// Creates a request codec around an explicitly bounded REST adapter.
    #[must_use]
    pub const fn new(rest: XaiRestAdapter) -> Self {
        Self { rest }
    }

    /// Converts a Responses create body into a `response.create` WebSocket
    /// text message. HTTP-only fields are removed by the REST adapter.
    pub fn encode_response_create(
        &self,
        body: &[u8],
        policy: LossPolicy,
    ) -> Result<EncodedXaiRealtimeRequest, XaiRealtimeError> {
        let prepared = self.rest.prepare_request(
            XaiRestEndpoint::Responses,
            XaiRestTransport::WebSocket,
            body,
            policy,
        )?;
        let value: Value = serde_json::from_slice(&prepared.body)?;
        let object = value.as_object().ok_or(XaiRealtimeError::RootNotObject)?;
        let model = required_string(object, "model")?.to_owned();
        let previous_response_id = optional_string(object, "previous_response_id")?;
        let generate = optional_bool(object, "generate")?.unwrap_or(true);
        Ok(EncodedXaiRealtimeRequest {
            body: prepared.body,
            model,
            previous_response_id,
            generate,
            report: prepared.report,
        })
    }
}

#[derive(Clone, Debug)]
struct ToolState {
    call_id: String,
    arguments: String,
    open: bool,
}

#[derive(Clone, Debug)]
struct ResponseState {
    id: String,
    text_blocks: BTreeSet<String>,
    reasoning_blocks: BTreeSet<String>,
    tools: BTreeMap<String, ToolState>,
    saw_tool_call: bool,
}

impl ResponseState {
    fn new(id: String) -> Self {
        Self {
            id,
            text_blocks: BTreeSet::new(),
            reasoning_blocks: BTreeSet::new(),
            tools: BTreeMap::new(),
            saw_tool_call: false,
        }
    }

    fn has_open_blocks(&self) -> bool {
        !self.text_blocks.is_empty()
            || !self.reasoning_blocks.is_empty()
            || self.tools.values().any(|tool| tool.open)
    }
}

/// Stateful xAI Responses WebSocket server-event decoder.
///
/// One instance owns one socket. It accepts sequential turns, resets semantic
/// sequence numbers between turns, rejects multiplexed response starts, and
/// retains every input event for native forwarding.
#[derive(Clone, Debug)]
pub struct XaiRealtimeEventDecoder {
    limits: XaiRealtimeLimits,
    active: Option<ResponseState>,
    terminal: bool,
    next_sequence: u64,
    last_wire_sequence: Option<u64>,
}

impl Default for XaiRealtimeEventDecoder {
    fn default() -> Self {
        Self::new(XaiRealtimeLimits::default())
    }
}

impl XaiRealtimeEventDecoder {
    /// Creates a decoder with explicit message and tool-argument bounds.
    #[must_use]
    pub const fn new(limits: XaiRealtimeLimits) -> Self {
        Self {
            limits,
            active: None,
            terminal: false,
            next_sequence: 0,
            last_wire_sequence: None,
        }
    }

    /// Decodes one UTF-8 JSON WebSocket text-message payload.
    pub fn decode_message(
        &mut self,
        input: &[u8],
    ) -> Result<DecodedXaiRealtimeEvent, XaiRealtimeError> {
        if input.len() > self.limits.max_message_bytes {
            return Err(XaiRealtimeError::MessageTooLarge {
                observed: input.len(),
                limit: self.limits.max_message_bytes,
            });
        }
        let value: Value = serde_json::from_slice(input)?;
        let object = value.as_object().ok_or(XaiRealtimeError::RootNotObject)?;
        let event_type = required_string(object, "type")?.to_owned();
        self.begin_event(&event_type, object)?;
        let (kind, semantic_kinds) = self.decode_event(&event_type, object, input)?;
        let semantic_events = semantic_kinds
            .into_iter()
            .map(|(kind, block_id)| self.semantic_event(kind, block_id))
            .collect();
        Ok(DecodedXaiRealtimeEvent {
            event_type,
            kind,
            semantic_events,
            raw: PreservedJson::from_bytes(input.to_vec())?,
        })
    }

    /// Verifies that the socket did not end during an active turn.
    pub fn finish(&self) -> Result<(), XaiRealtimeError> {
        if self.active.is_some() && !self.terminal {
            Err(XaiRealtimeError::IncompleteResponse)
        } else {
            Ok(())
        }
    }

    fn begin_event(
        &mut self,
        event_type: &str,
        object: &Map<String, Value>,
    ) -> Result<(), XaiRealtimeError> {
        if self.terminal && matches!(event_type, "response.created" | "error") {
            self.reset_turn();
        } else if self.terminal {
            return Err(lifecycle_error(
                event_type,
                "event appeared after a terminal event",
            ));
        }
        let Some(sequence) = object.get("sequence_number") else {
            return Ok(());
        };
        let sequence = sequence
            .as_u64()
            .ok_or_else(|| invalid_field("sequence_number", "must be an unsigned integer"))?;
        if let Some(previous) = self.last_wire_sequence {
            if sequence <= previous {
                return Err(XaiRealtimeError::NonMonotonicSequence {
                    previous,
                    actual: sequence,
                });
            }
        }
        self.last_wire_sequence = Some(sequence);
        Ok(())
    }

    fn decode_event(
        &mut self,
        event_type: &str,
        object: &Map<String, Value>,
        input: &[u8],
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        match event_type {
            "response.created" => self.decode_response_created(object),
            "response.content_part.added" => self.decode_content_part_added(object, input),
            "response.output_text.delta" => self.decode_text_delta(object),
            "response.output_text.done" => self.decode_text_done(object),
            "response.reasoning_summary_part.added" | "response.reasoning_part.added" => {
                self.decode_reasoning_start(object)
            }
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                self.decode_reasoning_delta(object)
            }
            "response.reasoning_summary_text.done" | "response.reasoning_text.done" => {
                self.decode_reasoning_done(object)
            }
            "response.output_item.added" => self.decode_output_item_added(object, input),
            "response.function_call_arguments.delta" => self.decode_tool_delta(object),
            "response.function_call_arguments.done" => self.decode_tool_done(object),
            "response.output_item.done" => self.decode_output_item_done(object, input),
            "response.refusal.delta" => self.decode_refusal_delta(object),
            "response.completed" => self.decode_response_completed(object),
            "response.incomplete" => self.decode_response_incomplete(object),
            "response.failed" => self.decode_response_failed(object),
            "response.cancelled" => self.decode_response_cancelled(object),
            "error" => self.decode_error(object),
            _ => {
                self.require_active(event_type)?;
                Ok((
                    XaiRealtimeEventKind::Other(event_type.to_owned()),
                    opaque_kind(input),
                ))
            }
        }
    }

    fn decode_response_created(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        if self.active.is_some() {
            return Err(lifecycle_error(
                "response.created",
                "a response is already active on this serial connection",
            ));
        }
        let response = required_object(object, "response")?;
        let id = required_string(response, "id")?.to_owned();
        let model = optional_string(response, "model")?;
        self.active = Some(ResponseState::new(id.clone()));
        Ok((
            XaiRealtimeEventKind::ResponseCreated,
            one_kind(StreamEventKind::response_start(Some(id), model), None),
        ))
    }

    fn decode_content_part_added(
        &mut self,
        object: &Map<String, Value>,
        input: &[u8],
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let part = required_object(object, "part")?;
        if required_string(part, "type")? != "output_text" {
            return Ok((
                XaiRealtimeEventKind::Other("response.content_part.added".to_owned()),
                opaque_kind(input),
            ));
        }
        let block_id = content_block_id(object)?;
        let inserted = self
            .active_mut("response.content_part.added")?
            .text_blocks
            .insert(block_id.clone());
        if !inserted {
            return Err(lifecycle_error(
                "response.content_part.added",
                "text block started more than once",
            ));
        }
        Ok((
            XaiRealtimeEventKind::TextStarted,
            one_kind(StreamEventKind::TextStart, Some(block_id)),
        ))
    }

    fn decode_text_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let block_id = content_block_id(object)?;
        self.require_text_block("response.output_text.delta", &block_id)?;
        let delta = required_string(object, "delta")?.to_owned();
        Ok((
            XaiRealtimeEventKind::TextDelta,
            one_kind(StreamEventKind::text_delta(delta), Some(block_id)),
        ))
    }

    fn decode_text_done(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let block_id = content_block_id(object)?;
        let removed = self
            .active_mut("response.output_text.done")?
            .text_blocks
            .remove(&block_id);
        if !removed {
            return Err(lifecycle_error(
                "response.output_text.done",
                "text block is not open",
            ));
        }
        Ok((
            XaiRealtimeEventKind::TextDone,
            one_kind(StreamEventKind::TextEnd, Some(block_id)),
        ))
    }

    fn decode_reasoning_start(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let block_id = reasoning_block_id(object)?;
        let inserted = self
            .active_mut("response.reasoning_summary_part.added")?
            .reasoning_blocks
            .insert(block_id.clone());
        if !inserted {
            return Err(lifecycle_error(
                "response.reasoning_summary_part.added",
                "reasoning block started more than once",
            ));
        }
        Ok((
            XaiRealtimeEventKind::ReasoningStarted,
            one_kind(StreamEventKind::ReasoningStart, Some(block_id)),
        ))
    }

    fn decode_reasoning_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let block_id = reasoning_block_id(object)?;
        let delta = required_string(object, "delta")?.to_owned();
        let inserted = self
            .active_mut("response.reasoning_summary_text.delta")?
            .reasoning_blocks
            .insert(block_id.clone());
        let mut kinds = Vec::with_capacity(2);
        if inserted {
            kinds.push((StreamEventKind::ReasoningStart, Some(block_id.clone())));
        }
        kinds.push((StreamEventKind::reasoning_delta(delta), Some(block_id)));
        Ok((XaiRealtimeEventKind::ReasoningDelta, kinds))
    }

    fn decode_reasoning_done(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let block_id = reasoning_block_id(object)?;
        let removed = self
            .active_mut("response.reasoning_summary_text.done")?
            .reasoning_blocks
            .remove(&block_id);
        if !removed {
            return Err(lifecycle_error(
                "response.reasoning_summary_text.done",
                "reasoning block is not open",
            ));
        }
        Ok((
            XaiRealtimeEventKind::ReasoningDone,
            one_kind(
                StreamEventKind::ReasoningEnd { reasoning: None },
                Some(block_id),
            ),
        ))
    }

    fn decode_output_item_added(
        &mut self,
        object: &Map<String, Value>,
        input: &[u8],
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let item = required_object(object, "item")?;
        if required_string(item, "type")? != "function_call" {
            return Ok((
                XaiRealtimeEventKind::Other("response.output_item.added".to_owned()),
                opaque_kind(input),
            ));
        }
        let item_id = required_string(item, "id")?.to_owned();
        let call_id = required_string(item, "call_id")?.to_owned();
        let name = required_string(item, "name")?.to_owned();
        let state = self.active_mut("response.output_item.added")?;
        if state.tools.contains_key(&item_id) {
            return Err(lifecycle_error(
                "response.output_item.added",
                "function call item started more than once",
            ));
        }
        state.tools.insert(
            item_id,
            ToolState {
                call_id: call_id.clone(),
                arguments: String::new(),
                open: true,
            },
        );
        state.saw_tool_call = true;
        Ok((
            XaiRealtimeEventKind::ToolCallStarted,
            one_kind(StreamEventKind::ToolCallStart { id: call_id, name }, None),
        ))
    }

    fn decode_tool_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let item_id = required_string(object, "item_id")?;
        let delta = required_string(object, "delta")?;
        let limit = self.limits.max_tool_arguments_bytes;
        let call_id = {
            let tool = self.tool_mut("response.function_call_arguments.delta", item_id)?;
            if !tool.open {
                return Err(lifecycle_error(
                    "response.function_call_arguments.delta",
                    "function call is already closed",
                ));
            }
            if tool.arguments.len().saturating_add(delta.len()) > limit {
                return Err(XaiRealtimeError::ToolArgumentsTooLarge { limit });
            }
            tool.arguments.push_str(delta);
            tool.call_id.clone()
        };
        Ok((
            XaiRealtimeEventKind::ToolArgumentsDelta,
            one_kind(
                StreamEventKind::ToolCallDelta {
                    id: call_id,
                    arguments: delta.to_owned(),
                },
                None,
            ),
        ))
    }

    fn decode_tool_done(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let item_id = required_string(object, "item_id")?;
        let final_arguments = optional_string(object, "arguments")?;
        let call_id = self.close_tool(
            "response.function_call_arguments.done",
            item_id,
            final_arguments.as_deref(),
        )?;
        Ok((
            XaiRealtimeEventKind::ToolCallDone,
            one_kind(StreamEventKind::ToolCallEnd { id: call_id }, None),
        ))
    }

    fn decode_output_item_done(
        &mut self,
        object: &Map<String, Value>,
        input: &[u8],
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        self.require_active("response.output_item.done")?;
        let item = required_object(object, "item")?;
        if required_string(item, "type")? != "function_call" {
            return Ok((
                XaiRealtimeEventKind::Other("response.output_item.done".to_owned()),
                opaque_kind(input),
            ));
        }
        let item_id = required_string(item, "id")?;
        let arguments = optional_string(item, "arguments")?;
        let is_open = self
            .active
            .as_ref()
            .and_then(|state| state.tools.get(item_id))
            .is_some_and(|tool| tool.open);
        if !is_open {
            return Ok((XaiRealtimeEventKind::ToolCallDone, opaque_kind(input)));
        }
        let call_id =
            self.close_tool("response.output_item.done", item_id, arguments.as_deref())?;
        Ok((
            XaiRealtimeEventKind::ToolCallDone,
            one_kind(StreamEventKind::ToolCallEnd { id: call_id }, None),
        ))
    }

    fn decode_refusal_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        self.require_active("response.refusal.delta")?;
        let delta = required_string(object, "delta")?.to_owned();
        Ok((
            XaiRealtimeEventKind::Other("response.refusal.delta".to_owned()),
            one_kind(StreamEventKind::Refusal { text: delta }, None),
        ))
    }

    fn decode_response_completed(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let response = self.validate_terminal_response("response.completed", object)?;
        let usage = response.get("usage").map(parse_usage).transpose()?;
        let saw_tool_call = self
            .active
            .as_ref()
            .ok_or_else(|| lifecycle_error("response.completed", "no response is active"))?
            .saw_tool_call;
        let finish_reason = if saw_tool_call {
            FinishReason::ToolCall
        } else {
            FinishReason::Stop
        };
        self.terminal = true;
        Ok((
            XaiRealtimeEventKind::ResponseCompleted,
            one_kind(StreamEventKind::completion(finish_reason, usage), None),
        ))
    }

    fn decode_response_incomplete(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let response = self.validate_terminal_response("response.incomplete", object)?;
        let usage = response.get("usage").map(parse_usage).transpose()?;
        let reason = response
            .get("incomplete_details")
            .and_then(Value::as_object)
            .and_then(|details| details.get("reason"))
            .and_then(Value::as_str)
            .unwrap_or("incomplete");
        let finish_reason = match reason {
            "max_output_tokens" => FinishReason::Length,
            other => FinishReason::Other(other.to_owned()),
        };
        self.terminal = true;
        Ok((
            XaiRealtimeEventKind::ResponseCompleted,
            one_kind(StreamEventKind::completion(finish_reason, usage), None),
        ))
    }

    fn decode_response_failed(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let response = self.validate_response_id("response.failed", object)?;
        let error = response
            .get("error")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_field("response.error", "must be an object"))?;
        let stream_error = parse_stream_error(error, None)?;
        let mut kinds = self.close_open_blocks();
        kinds.push((
            StreamEventKind::Failure {
                error: stream_error,
            },
            None,
        ));
        self.terminal = true;
        Ok((XaiRealtimeEventKind::ResponseFailed, kinds))
    }

    fn decode_response_cancelled(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        self.validate_response_id("response.cancelled", object)?;
        let mut kinds = self.close_open_blocks();
        kinds.push((
            StreamEventKind::Failure {
                error: StreamError::new("response_cancelled", "xAI response was cancelled"),
            },
            None,
        ));
        self.terminal = true;
        Ok((XaiRealtimeEventKind::ResponseFailed, kinds))
    }

    fn decode_error(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(XaiRealtimeEventKind, SemanticKinds), XaiRealtimeError> {
        let error = required_object(object, "error")?;
        let status = object.get("status").and_then(Value::as_u64);
        let stream_error = parse_stream_error(error, status)?;
        let mut kinds = self.close_open_blocks();
        kinds.push((
            StreamEventKind::Failure {
                error: stream_error,
            },
            None,
        ));
        self.terminal = true;
        Ok((XaiRealtimeEventKind::Error, kinds))
    }

    fn validate_terminal_response<'a>(
        &mut self,
        event_type: &str,
        object: &'a Map<String, Value>,
    ) -> Result<&'a Map<String, Value>, XaiRealtimeError> {
        let response = self.validate_response_id(event_type, object)?;
        if self.active_mut(event_type)?.has_open_blocks() {
            return Err(lifecycle_error(
                event_type,
                "response became terminal while an output block was open",
            ));
        }
        Ok(response)
    }

    fn validate_response_id<'a>(
        &mut self,
        event_type: &str,
        object: &'a Map<String, Value>,
    ) -> Result<&'a Map<String, Value>, XaiRealtimeError> {
        let response = required_object(object, "response")?;
        let response_id = required_string(response, "id")?;
        let state = self.active_mut(event_type)?;
        if state.id != response_id {
            return Err(lifecycle_error(
                event_type,
                "response ID changed within one turn",
            ));
        }
        Ok(response)
    }

    fn close_tool(
        &mut self,
        event_type: &str,
        item_id: &str,
        final_arguments: Option<&str>,
    ) -> Result<String, XaiRealtimeError> {
        let limit = self.limits.max_tool_arguments_bytes;
        let tool = self.tool_mut(event_type, item_id)?;
        if !tool.open {
            return Err(lifecycle_error(
                event_type,
                "function call is already closed",
            ));
        }
        if let Some(final_arguments) = final_arguments {
            if final_arguments.len() > limit {
                return Err(XaiRealtimeError::ToolArgumentsTooLarge { limit });
            }
            if !tool.arguments.is_empty() && tool.arguments != final_arguments {
                return Err(lifecycle_error(
                    event_type,
                    "final arguments do not match streamed fragments",
                ));
            }
            if tool.arguments.is_empty() {
                tool.arguments.push_str(final_arguments);
            }
        }
        tool.open = false;
        Ok(tool.call_id.clone())
    }

    fn close_open_blocks(&mut self) -> SemanticKinds {
        let Some(state) = self.active.as_mut() else {
            return Vec::new();
        };
        let mut kinds = Vec::new();
        for block_id in std::mem::take(&mut state.text_blocks) {
            kinds.push((StreamEventKind::TextEnd, Some(block_id)));
        }
        for block_id in std::mem::take(&mut state.reasoning_blocks) {
            kinds.push((
                StreamEventKind::ReasoningEnd { reasoning: None },
                Some(block_id),
            ));
        }
        for tool in state.tools.values_mut().filter(|tool| tool.open) {
            tool.open = false;
            kinds.push((
                StreamEventKind::ToolCallEnd {
                    id: tool.call_id.clone(),
                },
                None,
            ));
        }
        kinds
    }

    fn require_text_block(&self, event_type: &str, block_id: &str) -> Result<(), XaiRealtimeError> {
        let state = self
            .active
            .as_ref()
            .ok_or_else(|| lifecycle_error(event_type, "no response is active"))?;
        if state.text_blocks.contains(block_id) {
            Ok(())
        } else {
            Err(lifecycle_error(event_type, "text block is not open"))
        }
    }

    fn require_active(&self, event_type: &str) -> Result<(), XaiRealtimeError> {
        if self.active.is_some() {
            Ok(())
        } else {
            Err(lifecycle_error(event_type, "no response is active"))
        }
    }

    fn active_mut(&mut self, event_type: &str) -> Result<&mut ResponseState, XaiRealtimeError> {
        self.active
            .as_mut()
            .ok_or_else(|| lifecycle_error(event_type, "no response is active"))
    }

    fn tool_mut(
        &mut self,
        event_type: &str,
        item_id: &str,
    ) -> Result<&mut ToolState, XaiRealtimeError> {
        self.active_mut(event_type)?
            .tools
            .get_mut(item_id)
            .ok_or_else(|| lifecycle_error(event_type, "function call item is unknown"))
    }

    fn semantic_event(&mut self, kind: StreamEventKind, block_id: Option<String>) -> StreamEvent {
        self.next_sequence = self.next_sequence.saturating_add(1);
        let event = StreamEvent::new(self.next_sequence, kind);
        match block_id {
            Some(block_id) => event.with_block_id(block_id),
            None => event,
        }
    }

    fn reset_turn(&mut self) {
        self.active = None;
        self.terminal = false;
        self.next_sequence = 0;
        self.last_wire_sequence = None;
    }
}

type SemanticKinds = Vec<(StreamEventKind, Option<String>)>;

fn one_kind(kind: StreamEventKind, block_id: Option<String>) -> SemanticKinds {
    vec![(kind, block_id)]
}

fn opaque_kind(input: &[u8]) -> SemanticKinds {
    one_kind(
        StreamEventKind::Opaque {
            media_type: REALTIME_EVENT_MEDIA_TYPE.to_owned(),
            data: input.to_vec(),
        },
        None,
    )
}

fn invalid_field(field: impl Into<String>, reason: &'static str) -> XaiRealtimeError {
    XaiRealtimeError::InvalidField {
        field: field.into(),
        reason,
    }
}

fn lifecycle_error(event_type: &str, reason: impl Into<String>) -> XaiRealtimeError {
    XaiRealtimeError::InvalidLifecycle {
        event_type: event_type.to_owned(),
        reason: reason.into(),
    }
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, XaiRealtimeError> {
    object
        .get(field)
        .ok_or_else(|| XaiRealtimeError::MissingField(field.to_owned()))?
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_field(field, "must be a non-empty string"))
}

fn optional_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, XaiRealtimeError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(_) => Err(invalid_field(field, "must be a non-empty string or null")),
    }
}

fn optional_bool(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<bool>, XaiRealtimeError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_field(field, "must be a boolean or null")),
    }
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, XaiRealtimeError> {
    object
        .get(field)
        .ok_or_else(|| XaiRealtimeError::MissingField(field.to_owned()))?
        .as_object()
        .ok_or_else(|| invalid_field(field, "must be an object"))
}

fn required_index(object: &Map<String, Value>, field: &str) -> Result<u64, XaiRealtimeError> {
    object
        .get(field)
        .ok_or_else(|| XaiRealtimeError::MissingField(field.to_owned()))?
        .as_u64()
        .ok_or_else(|| invalid_field(field, "must be an unsigned integer"))
}

fn content_block_id(object: &Map<String, Value>) -> Result<String, XaiRealtimeError> {
    let item_id = required_string(object, "item_id")?;
    let content_index = required_index(object, "content_index")?;
    Ok(format!("xai-text-{item_id}-{content_index}"))
}

fn reasoning_block_id(object: &Map<String, Value>) -> Result<String, XaiRealtimeError> {
    let item_id = required_string(object, "item_id")?;
    let index = object
        .get("summary_index")
        .or_else(|| object.get("content_index"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Ok(format!("xai-reasoning-{item_id}-{index}"))
}

fn parse_usage(value: &Value) -> Result<Usage, XaiRealtimeError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_field("response.usage", "must be an object"))?;
    let input_tokens = optional_count(object, "input_tokens")?.unwrap_or(0);
    let output_tokens = optional_count(object, "output_tokens")?.unwrap_or(0);
    let mut usage = Usage {
        input_tokens,
        output_tokens,
        reasoning_tokens: None,
        cached_input_tokens: None,
        total_tokens: optional_count(object, "total_tokens")?,
        details: BTreeMap::new(),
    };
    if let Some(details) = optional_nested_object(object, "input_tokens_details")? {
        usage.cached_input_tokens = optional_count(details, "cached_tokens")?;
    }
    if let Some(details) = optional_nested_object(object, "output_tokens_details")? {
        usage.reasoning_tokens = optional_count(details, "reasoning_tokens")?;
    }
    for field in ["cost_in_usd_ticks", "num_sources_used"] {
        if let Some(value) = optional_count(object, field)? {
            usage.details.insert(field.to_owned(), value);
        }
    }
    Ok(usage)
}

fn optional_nested_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a Map<String, Value>>, XaiRealtimeError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(invalid_field(
            format!("response.usage.{field}"),
            "must be an object or null",
        )),
    }
}

fn optional_count(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, XaiRealtimeError> {
    object
        .get(field)
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                invalid_field(
                    format!("response.usage.{field}"),
                    "must be an unsigned integer",
                )
            })
        })
        .transpose()
}

fn parse_stream_error(
    object: &Map<String, Value>,
    status: Option<u64>,
) -> Result<StreamError, XaiRealtimeError> {
    let code = optional_string(object, "code")?.unwrap_or_else(|| "xai_error".to_owned());
    let message = required_string(object, "message")?.to_owned();
    let retryable = code == "websocket_connection_limit_reached"
        || status.is_some_and(|status| matches!(status, 408 | 409 | 425 | 429) || status >= 500);
    let details = PreservedJson::from_value(Value::Object(object.clone()))?;
    let mut error = StreamError::new(code, message).with_retryable(retryable);
    error.details = Some(details);
    Ok(error)
}

#[cfg(test)]
mod tests {
    use pooler_protocol::{FinishReason, LossPolicy, StreamEventKind, StreamValidator};
    use serde_json::Value;

    use super::{
        XaiRealtimeError, XaiRealtimeEventDecoder, XaiRealtimeEventKind, XaiRealtimeLimits,
        XaiRealtimeRequestCodec,
    };

    #[test]
    fn request_codec_supports_warmup_and_continuation() {
        let encoded = XaiRealtimeRequestCodec::default()
            .encode_response_create(
                br#"{
                  "model":"grok-4.6",
                  "input":[{"type":"function_call_output","call_id":"call-1","output":"ok"}],
                  "previous_response_id":"resp-1",
                  "store":false,
                  "stream":true,
                  "background":false,
                  "generate":false
                }"#,
                LossPolicy::Reject,
            )
            .expect("response.create");
        let value: Value = serde_json::from_slice(&encoded.body).expect("JSON");
        assert_eq!(value["type"], "response.create");
        assert_eq!(encoded.previous_response_id.as_deref(), Some("resp-1"));
        assert!(!encoded.generate);
        assert!(value.get("stream").is_none());
        assert!(value.get("background").is_none());
    }

    #[test]
    fn rejects_non_monotonic_provider_sequence() {
        let mut decoder = XaiRealtimeEventDecoder::default();
        decoder
            .decode_message(
                br#"{"type":"response.created","sequence_number":2,"response":{"id":"resp-1","model":"grok"}}"#,
            )
            .expect("start");
        let error = decoder
            .decode_message(
                br#"{"type":"response.in_progress","sequence_number":2,"response":{"id":"resp-1"}}"#,
            )
            .expect_err("sequence must increase");
        assert!(matches!(
            error,
            XaiRealtimeError::NonMonotonicSequence { .. }
        ));
    }

    #[test]
    fn enforces_accumulated_tool_argument_limit() {
        let mut decoder = XaiRealtimeEventDecoder::new(XaiRealtimeLimits {
            max_message_bytes: 4096,
            max_tool_arguments_bytes: 3,
        });
        decoder
            .decode_message(
                br#"{"type":"response.created","response":{"id":"resp-1","model":"grok"}}"#,
            )
            .expect("start");
        decoder
            .decode_message(
                br#"{"type":"response.output_item.added","output_index":0,"item":{"id":"fc-1","type":"function_call","call_id":"call-1","name":"lookup","arguments":""}}"#,
            )
            .expect("tool start");
        let error = decoder
            .decode_message(
                br#"{"type":"response.function_call_arguments.delta","item_id":"fc-1","output_index":0,"delta":"four"}"#,
            )
            .expect_err("argument bound");
        assert!(matches!(
            error,
            XaiRealtimeError::ToolArgumentsTooLarge { limit: 3 }
        ));
    }

    #[test]
    fn connection_limit_error_requests_reconnect() {
        let mut decoder = XaiRealtimeEventDecoder::default();
        let decoded = decoder
            .decode_message(
                br#"{
                  "type":"error",
                  "status":400,
                  "error":{"type":"invalid_request_error","code":"websocket_connection_limit_reached","message":"connection limit reached"}
                }"#,
            )
            .expect("connection error");
        assert_eq!(decoded.kind, XaiRealtimeEventKind::Error);
        assert!(matches!(
            &decoded.semantic_events[0].kind,
            StreamEventKind::Failure { error } if error.retryable
        ));
    }

    #[test]
    fn decoder_accepts_a_new_turn_after_completion() {
        let mut decoder = XaiRealtimeEventDecoder::default();
        for response_id in ["resp-1", "resp-2"] {
            let start = format!(
                r#"{{"type":"response.created","response":{{"id":"{response_id}","model":"grok"}}}}"#
            );
            let complete = format!(
                r#"{{"type":"response.completed","response":{{"id":"{response_id}","usage":{{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}}}}"#
            );
            let started = decoder
                .decode_message(start.as_bytes())
                .expect("response start");
            assert_eq!(started.semantic_events[0].sequence, 1);
            let completed = decoder
                .decode_message(complete.as_bytes())
                .expect("response completion");
            assert!(matches!(
                completed.semantic_events[0].kind,
                StreamEventKind::Completion {
                    finish_reason: FinishReason::Stop,
                    ..
                }
            ));
        }
    }

    #[test]
    fn semantic_lifecycle_from_text_events_is_valid() {
        let frames: [&[u8]; 5] = [
            br#"{"type":"response.created","response":{"id":"resp-1","model":"grok"}}"#,
            br#"{"type":"response.content_part.added","item_id":"msg-1","output_index":0,"content_index":0,"part":{"type":"output_text","text":""}}"#,
            br#"{"type":"response.output_text.delta","item_id":"msg-1","output_index":0,"content_index":0,"delta":"hello"}"#,
            br#"{"type":"response.output_text.done","item_id":"msg-1","output_index":0,"content_index":0,"text":"hello"}"#,
            br#"{"type":"response.completed","response":{"id":"resp-1","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}"#,
        ];
        let mut decoder = XaiRealtimeEventDecoder::default();
        let mut validator = StreamValidator::default();
        for frame in frames {
            let decoded = decoder.decode_message(frame).expect("frame");
            for event in decoded.semantic_events {
                validator.accept(&event).expect("valid semantic event");
            }
        }
        decoder.finish().expect("complete socket turn");
    }

    #[test]
    fn failure_closes_open_blocks_before_terminal_event() {
        let frames: [&[u8]; 3] = [
            br#"{"type":"response.created","response":{"id":"resp-1","model":"grok"}}"#,
            br#"{"type":"response.content_part.added","item_id":"msg-1","output_index":0,"content_index":0,"part":{"type":"output_text","text":""}}"#,
            br#"{"type":"response.failed","response":{"id":"resp-1","error":{"code":"server_error","message":"generation failed"}}}"#,
        ];
        let mut decoder = XaiRealtimeEventDecoder::default();
        let mut validator = StreamValidator::default();
        let mut terminal_kinds = Vec::new();
        for frame in frames {
            let decoded = decoder.decode_message(frame).expect("frame");
            terminal_kinds = decoded
                .semantic_events
                .iter()
                .map(|event| event.kind.clone())
                .collect();
            for event in decoded.semantic_events {
                validator.accept(&event).expect("valid semantic event");
            }
        }
        assert!(matches!(terminal_kinds[0], StreamEventKind::TextEnd));
        assert!(matches!(terminal_kinds[1], StreamEventKind::Failure { .. }));
    }

    #[test]
    fn unknown_response_event_retains_exact_json() {
        let start = br#"{"type":"response.created","response":{"id":"resp-1","model":"grok"}}"#;
        let extension = br#"{ "type": "response.xai_extension", "value": [1, 2] }"#;
        let mut decoder = XaiRealtimeEventDecoder::default();
        decoder.decode_message(start).expect("start");
        let decoded = decoder.decode_message(extension).expect("extension event");
        assert_eq!(decoded.raw.original_bytes(), extension);
        assert_eq!(
            decoded.kind,
            XaiRealtimeEventKind::Other("response.xai_extension".to_owned())
        );
        assert!(matches!(
            &decoded.semantic_events[0].kind,
            StreamEventKind::Opaque { data, .. } if data == extension
        ));
    }
}
