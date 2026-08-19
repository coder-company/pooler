//! Incremental semantic response events.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ConversionWarning, MediaSource, PreservedJson, ReasoningBlock};

/// Token usage reported by a provider.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Input/prompt tokens.
    #[serde(default)]
    pub input_tokens: u64,
    /// Generated/output tokens.
    #[serde(default)]
    pub output_tokens: u64,
    /// Optional reasoning token count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
    /// Optional cached input token count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    /// Provider-reported total.  If absent, encoders may calculate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    /// Provider-specific usage fields.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, u64>,
}

impl Usage {
    /// Creates usage with input and output counts and a calculated total.
    #[must_use]
    pub const fn new(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
            reasoning_tokens: None,
            cached_input_tokens: None,
            total_tokens: Some(input_tokens.saturating_add(output_tokens)),
            details: BTreeMap::new(),
        }
    }
}

/// Why a model response stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// The model completed normally.
    Stop,
    /// The output token limit was reached.
    Length,
    /// The model requested a tool call.
    ToolCall,
    /// Provider content policy stopped generation.
    ContentFilter,
    /// The provider returned an error terminal state.
    Error,
    /// A provider-specific finish reason.
    Other(String),
}

/// A terminal or non-terminal upstream failure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamError {
    /// Stable machine-readable code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Whether a route may consider retrying before downstream commitment.
    #[serde(default)]
    pub retryable: bool,
    /// Optional provider error document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<PreservedJson>,
}

impl StreamError {
    /// Creates a non-retryable stream error.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
            details: None,
        }
    }

    /// Sets the retryability classification.
    #[must_use]
    pub const fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }
}

/// One semantic response event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEventKind {
    /// Response identity and model metadata.
    ResponseStart {
        /// Provider response identifier.
        response_id: Option<String>,
        /// Resolved model identifier.
        model: Option<String>,
    },
    /// Provider response metadata.
    Metadata {
        /// Metadata fields.
        values: BTreeMap<String, String>,
    },
    /// Start of a text block.
    TextStart,
    /// Incremental text content.
    TextDelta {
        /// New text bytes as UTF-8.
        text: String,
    },
    /// End of a text block.
    TextEnd,
    /// Start of a reasoning block.
    ReasoningStart,
    /// Incremental reasoning text.
    ReasoningDelta {
        /// New reasoning text.
        text: String,
    },
    /// End of a reasoning block with optional final block state.
    ReasoningEnd {
        /// Final reasoning metadata.
        reasoning: Option<ReasoningBlock>,
    },
    /// Start of a tool-call block.
    ToolCallStart {
        /// Stable invocation identifier.
        id: String,
        /// Tool name.
        name: String,
    },
    /// Incremental tool-call argument bytes.
    ToolCallDelta {
        /// Invocation identifier.
        id: String,
        /// Argument JSON fragment.
        arguments: String,
    },
    /// End of a tool-call block.
    ToolCallEnd {
        /// Invocation identifier.
        id: String,
    },
    /// A media result or media delta.
    Media {
        /// Media MIME type.
        media_type: String,
        /// Media bytes or URI.
        source: MediaSource,
    },
    /// Token usage update.
    Usage {
        /// Usage snapshot.
        usage: Usage,
    },
    /// Model refusal content.
    Refusal {
        /// Refusal text.
        text: String,
    },
    /// A conversion or provider warning.
    Warning {
        /// Structured warning.
        warning: ConversionWarning,
    },
    /// Successful response completion.
    Completion {
        /// Why the model stopped.
        finish_reason: FinishReason,
        /// Optional final usage snapshot.
        usage: Option<Usage>,
    },
    /// Terminal response failure.
    Failure {
        /// Failure details.
        error: StreamError,
    },
    /// Provider event with no common semantic representation.
    Opaque {
        /// Event media type.
        media_type: String,
        /// Raw event bytes.
        data: Vec<u8>,
    },
}

impl StreamEventKind {
    /// Creates a response-start event.
    #[must_use]
    pub fn response_start(response_id: Option<String>, model: Option<String>) -> Self {
        Self::ResponseStart { response_id, model }
    }

    /// Creates a text delta event.
    #[must_use]
    pub fn text_delta(text: impl Into<String>) -> Self {
        Self::TextDelta { text: text.into() }
    }

    /// Creates a reasoning delta event.
    #[must_use]
    pub fn reasoning_delta(text: impl Into<String>) -> Self {
        Self::ReasoningDelta { text: text.into() }
    }

    /// Creates a completion event.
    #[must_use]
    pub fn completion(finish_reason: FinishReason, usage: Option<Usage>) -> Self {
        Self::Completion {
            finish_reason,
            usage,
        }
    }

    /// Returns whether this event ends the response stream.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completion { .. } | Self::Failure { .. })
    }

    fn block_action(&self) -> Option<BlockAction<'_>> {
        match self {
            Self::TextStart => Some(BlockAction::Start),
            Self::TextDelta { .. } => Some(BlockAction::Continue),
            Self::TextEnd => Some(BlockAction::End),
            Self::ReasoningStart => Some(BlockAction::Start),
            Self::ReasoningDelta { .. } => Some(BlockAction::Continue),
            Self::ReasoningEnd { .. } => Some(BlockAction::End),
            Self::ToolCallStart { id, .. } => Some(BlockAction::StartWithId(id)),
            Self::ToolCallDelta { id, .. } => Some(BlockAction::ContinueWithId(id)),
            Self::ToolCallEnd { id } => Some(BlockAction::EndWithId(id)),
            Self::ResponseStart { .. }
            | Self::Metadata { .. }
            | Self::Media { .. }
            | Self::Usage { .. }
            | Self::Refusal { .. }
            | Self::Warning { .. }
            | Self::Completion { .. }
            | Self::Failure { .. }
            | Self::Opaque { .. } => None,
        }
    }
}

enum BlockAction<'a> {
    Start,
    Continue,
    End,
    StartWithId(&'a str),
    ContinueWithId(&'a str),
    EndWithId(&'a str),
}

/// A stream event envelope carrying monotonic ordering and an optional stable
/// block identifier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamEvent {
    /// Source ordering sequence.  It must increase strictly within a stream.
    pub sequence: u64,
    /// Stable text/reasoning block identifier.  Tool events may use their own
    /// invocation identifier when this field is omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_id: Option<String>,
    /// Event payload.
    pub kind: StreamEventKind,
    /// Provider-specific event state.
    #[serde(default, skip_serializing_if = "crate::Extensions::is_empty")]
    pub extensions: crate::Extensions,
}

impl StreamEvent {
    /// Creates an event envelope.
    #[must_use]
    pub fn new(sequence: u64, kind: StreamEventKind) -> Self {
        Self {
            sequence,
            block_id: None,
            kind,
            extensions: crate::Extensions::default(),
        }
    }

    /// Attaches a stable block identifier.
    #[must_use]
    pub fn with_block_id(mut self, block_id: impl Into<String>) -> Self {
        self.block_id = Some(block_id.into());
        self
    }

    /// Returns the effective block identifier for this event, including tool
    /// invocation IDs carried by tool event kinds.
    #[must_use]
    pub fn effective_block_id(&self) -> Option<&str> {
        self.block_id.as_deref().or(match &self.kind {
            StreamEventKind::ToolCallStart { id, .. }
            | StreamEventKind::ToolCallDelta { id, .. }
            | StreamEventKind::ToolCallEnd { id } => Some(id.as_str()),
            _ => None,
        })
    }

    /// Validates this event as the first event in a stream.
    pub fn validate(&self) -> Result<(), StreamValidationError> {
        let mut validator = StreamValidator::default();
        validator.accept(self)
    }
}

/// Validation failures for ordered semantic streams.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StreamValidationError {
    /// Event sequence was not strictly increasing.
    #[error("event sequence {actual} is not greater than previous sequence {previous}")]
    NonMonotonicSequence {
        /// Last accepted sequence.
        previous: u64,
        /// Rejected sequence.
        actual: u64,
    },
    /// A block lifecycle event did not carry a stable identifier.
    #[error("{event} requires a stable block identifier")]
    MissingBlockId {
        /// Event name.
        event: &'static str,
    },
    /// A block was started twice.
    #[error("block `{0}` was started more than once")]
    DuplicateBlock(String),
    /// A delta or end event referenced no open block.
    #[error("block `{0}` is not open")]
    UnknownBlock(String),
    /// A stream event appeared after completion or failure.
    #[error("event appeared after stream termination")]
    AfterTerminal,
    /// A response-start event appeared twice.
    #[error("response start appeared more than once")]
    DuplicateResponseStart,
}

/// Stateful validator for sequence numbers, block lifecycles, and terminal
/// stream behavior.
#[derive(Clone, Debug, Default)]
pub struct StreamValidator {
    last_sequence: Option<u64>,
    response_started: bool,
    terminal: bool,
    open_blocks: Vec<String>,
}

impl StreamValidator {
    /// Accepts one event or returns the invariant that it violated.
    pub fn accept(&mut self, event: &StreamEvent) -> Result<(), StreamValidationError> {
        if self.terminal {
            return Err(StreamValidationError::AfterTerminal);
        }
        if let Some(previous) = self.last_sequence {
            if event.sequence <= previous {
                return Err(StreamValidationError::NonMonotonicSequence {
                    previous,
                    actual: event.sequence,
                });
            }
        }

        if matches!(event.kind, StreamEventKind::ResponseStart { .. }) && self.response_started {
            return Err(StreamValidationError::DuplicateResponseStart);
        }

        if let Some(action) = event.kind.block_action() {
            let effective_id = event.effective_block_id();
            match action {
                BlockAction::Start => {
                    let id = effective_id.ok_or(StreamValidationError::MissingBlockId {
                        event: event_name(&event.kind),
                    })?;
                    self.start_block(id)?;
                }
                BlockAction::Continue => {
                    let id = effective_id.ok_or(StreamValidationError::MissingBlockId {
                        event: event_name(&event.kind),
                    })?;
                    self.continue_block(id)?;
                }
                BlockAction::End => {
                    let id = effective_id.ok_or(StreamValidationError::MissingBlockId {
                        event: event_name(&event.kind),
                    })?;
                    self.end_block(id)?;
                }
                BlockAction::StartWithId(id) => self.start_block(id)?,
                BlockAction::ContinueWithId(id) => self.continue_block(id)?,
                BlockAction::EndWithId(id) => self.end_block(id)?,
            }
        }

        if matches!(event.kind, StreamEventKind::ResponseStart { .. }) {
            self.response_started = true;
        }
        self.last_sequence = Some(event.sequence);
        if event.kind.is_terminal() {
            self.terminal = true;
        }
        Ok(())
    }

    fn start_block(&mut self, id: &str) -> Result<(), StreamValidationError> {
        if id.is_empty() {
            return Err(StreamValidationError::MissingBlockId { event: "block" });
        }
        if self.open_blocks.iter().any(|open| open == id) {
            return Err(StreamValidationError::DuplicateBlock(id.to_owned()));
        }
        self.open_blocks.push(id.to_owned());
        Ok(())
    }

    fn continue_block(&self, id: &str) -> Result<(), StreamValidationError> {
        if self.open_blocks.iter().any(|open| open == id) {
            Ok(())
        } else {
            Err(StreamValidationError::UnknownBlock(id.to_owned()))
        }
    }

    fn end_block(&mut self, id: &str) -> Result<(), StreamValidationError> {
        let Some(index) = self.open_blocks.iter().position(|open| open == id) else {
            return Err(StreamValidationError::UnknownBlock(id.to_owned()));
        };
        self.open_blocks.remove(index);
        Ok(())
    }

    /// Returns whether a terminal event has been accepted.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Returns currently open block identifiers.
    #[must_use]
    pub fn open_blocks(&self) -> &[String] {
        &self.open_blocks
    }

    /// Returns whether all block lifecycles have ended.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.open_blocks.is_empty()
    }
}

fn event_name(event: &StreamEventKind) -> &'static str {
    match event {
        StreamEventKind::TextStart => "text_start",
        StreamEventKind::TextDelta { .. } => "text_delta",
        StreamEventKind::TextEnd => "text_end",
        StreamEventKind::ReasoningStart => "reasoning_start",
        StreamEventKind::ReasoningDelta { .. } => "reasoning_delta",
        StreamEventKind::ReasoningEnd { .. } => "reasoning_end",
        StreamEventKind::ToolCallStart { .. } => "tool_call_start",
        StreamEventKind::ToolCallDelta { .. } => "tool_call_delta",
        StreamEventKind::ToolCallEnd { .. } => "tool_call_end",
        StreamEventKind::ResponseStart { .. }
        | StreamEventKind::Metadata { .. }
        | StreamEventKind::Media { .. }
        | StreamEventKind::Usage { .. }
        | StreamEventKind::Refusal { .. }
        | StreamEventKind::Warning { .. }
        | StreamEventKind::Completion { .. }
        | StreamEventKind::Failure { .. }
        | StreamEventKind::Opaque { .. } => "event",
    }
}

/// Alias used by callers that call semantic response events “events”.
pub type SemanticEvent = StreamEvent;

#[cfg(test)]
mod tests {
    use super::{
        FinishReason, StreamEvent, StreamEventKind, StreamValidationError, StreamValidator, Usage,
    };

    #[test]
    fn validator_enforces_block_lifecycle_and_sequence() {
        let mut validator = StreamValidator::default();
        validator
            .accept(&StreamEvent::new(1, StreamEventKind::TextStart).with_block_id("text-1"))
            .expect("start");
        validator
            .accept(
                &StreamEvent::new(2, StreamEventKind::text_delta("hello")).with_block_id("text-1"),
            )
            .expect("delta");
        validator
            .accept(&StreamEvent::new(3, StreamEventKind::TextEnd).with_block_id("text-1"))
            .expect("end");
        validator
            .accept(&StreamEvent::new(
                4,
                StreamEventKind::completion(FinishReason::Stop, Some(Usage::new(1, 2))),
            ))
            .expect("completion");
        assert!(validator.is_terminal());
        assert!(validator.is_drained());
        let error = validator
            .accept(&StreamEvent::new(
                5,
                StreamEventKind::Metadata {
                    values: Default::default(),
                },
            ))
            .expect_err("event after completion");
        assert_eq!(error, StreamValidationError::AfterTerminal);
    }

    #[test]
    fn tool_id_is_a_stable_block_id_when_envelope_omits_one() {
        let mut validator = StreamValidator::default();
        validator
            .accept(&StreamEvent::new(
                1,
                StreamEventKind::ToolCallStart {
                    id: "call-1".to_owned(),
                    name: "search".to_owned(),
                },
            ))
            .expect("tool start");
        validator
            .accept(&StreamEvent::new(
                2,
                StreamEventKind::ToolCallEnd {
                    id: "call-1".to_owned(),
                },
            ))
            .expect("tool end");
    }

    #[test]
    fn missing_text_block_id_is_rejected() {
        let error = StreamEvent::new(1, StreamEventKind::TextStart)
            .validate()
            .expect_err("missing block id");
        assert!(matches!(
            error,
            StreamValidationError::MissingBlockId { .. }
        ));
    }

    #[test]
    fn stream_events_serialize_with_stable_kind_tags() {
        let event = StreamEvent::new(9, StreamEventKind::text_delta("hi")).with_block_id("b");
        let value = serde_json::to_value(event).expect("serialize");
        assert_eq!(value["kind"]["type"], "text_delta");
        assert_eq!(value["sequence"], 9);
    }
}
