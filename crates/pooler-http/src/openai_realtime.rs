//! Bounded same-wire validation for OpenAI Realtime WebSocket sessions.

use base64::Engine as _;
use serde_json::{Map, Value};
use thiserror::Error;

pub(crate) const CLIENT_DECODER: &str = "decode.openai.realtime.client";
pub(crate) const SERVER_DECODER: &str = "decode.openai.realtime.events";

#[derive(Debug, Error)]
pub(crate) enum RealtimeValidationError {
    #[error("Realtime message is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("Realtime message must be a JSON object")]
    RootNotObject,
    #[error("Realtime message field `{0}` is missing or invalid")]
    InvalidField(&'static str),
    #[error("unsupported Realtime event `{0}`")]
    UnsupportedEvent(String),
    #[error("invalid Realtime lifecycle: {0}")]
    InvalidLifecycle(&'static str),
}

/// Stateful validator for one OpenAI Realtime connection.
#[derive(Debug, Default)]
pub(crate) struct OpenAiRealtimeValidator {
    session_created: bool,
    response_requested: bool,
    response_active: bool,
    input_audio_buffered: bool,
}

impl OpenAiRealtimeValidator {
    pub(crate) fn validate_client(
        &mut self,
        payload: &[u8],
    ) -> Result<(), RealtimeValidationError> {
        let object = parse_object(payload)?;
        let object = &object;
        let event_type = required_string(object, "type")?;
        match event_type {
            "session.update" => {
                required_object(object, "session")?;
            }
            "input_audio_buffer.append" => {
                let audio = required_string(object, "audio")?;
                if audio.is_empty()
                    || base64::engine::general_purpose::STANDARD
                        .decode(audio)
                        .is_err()
                {
                    return Err(RealtimeValidationError::InvalidField("audio"));
                }
                self.input_audio_buffered = true;
            }
            "input_audio_buffer.commit" => {
                if !self.input_audio_buffered {
                    return Err(RealtimeValidationError::InvalidLifecycle(
                        "input audio commit requires buffered audio",
                    ));
                }
                self.input_audio_buffered = false;
            }
            "input_audio_buffer.clear" => {
                self.input_audio_buffered = false;
            }
            "conversation.item.create" => {
                required_object(object, "item")?;
                optional_string(object, "previous_item_id")?;
            }
            "conversation.item.delete" | "conversation.item.retrieve" => {
                required_string(object, "item_id")?;
            }
            "conversation.item.truncate" => {
                required_string(object, "item_id")?;
                required_u64(object, "content_index")?;
                required_u64(object, "audio_end_ms")?;
            }
            "response.create" => {
                if self.response_requested || self.response_active {
                    return Err(RealtimeValidationError::InvalidLifecycle(
                        "response.create cannot overlap an active response",
                    ));
                }
                if let Some(response) = object.get("response") {
                    if !response.is_object() {
                        return Err(RealtimeValidationError::InvalidField("response"));
                    }
                }
                self.response_requested = true;
            }
            "response.cancel" => {
                if !self.response_requested && !self.response_active {
                    return Err(RealtimeValidationError::InvalidLifecycle(
                        "response.cancel requires a requested or active response",
                    ));
                }
                optional_string(object, "response_id")?;
            }
            "output_audio_buffer.clear" => {}
            other => return Err(RealtimeValidationError::UnsupportedEvent(other.to_owned())),
        }
        optional_string(object, "event_id")?;
        Ok(())
    }

    pub(crate) fn validate_server(
        &mut self,
        payload: &[u8],
    ) -> Result<(), RealtimeValidationError> {
        let object = parse_object(payload)?;
        let object = &object;
        let event_type = required_string(object, "type")?;
        required_string(object, "event_id")?;
        match event_type {
            "session.created" => {
                if self.session_created {
                    return Err(RealtimeValidationError::InvalidLifecycle(
                        "session.created may appear only once",
                    ));
                }
                required_object(object, "session")?;
                self.session_created = true;
            }
            "session.updated" => {
                require_session(self.session_created)?;
                required_object(object, "session")?;
            }
            "conversation.created" => {
                require_session(self.session_created)?;
                required_object(object, "conversation")?;
            }
            "response.created" => {
                require_session(self.session_created)?;
                if self.response_active {
                    return Err(RealtimeValidationError::InvalidLifecycle(
                        "response.created cannot overlap an active response",
                    ));
                }
                required_object(object, "response")?;
                self.response_requested = false;
                self.response_active = true;
            }
            "response.done" => {
                self.require_active_response()?;
                let response = required_object(object, "response")?;
                let status = required_string(response, "status")?;
                if !matches!(status, "completed" | "cancelled" | "failed" | "incomplete") {
                    return Err(RealtimeValidationError::InvalidField("response.status"));
                }
                self.response_requested = false;
                self.response_active = false;
            }
            event if is_response_progress_event(event) => {
                self.require_active_response()?;
                validate_response_progress(event, object)?;
            }
            event if is_conversation_event(event) || is_audio_buffer_event(event) => {
                require_session(self.session_created)?;
            }
            "rate_limits.updated" => {
                require_session(self.session_created)?;
                if !object.get("rate_limits").is_some_and(Value::is_array) {
                    return Err(RealtimeValidationError::InvalidField("rate_limits"));
                }
            }
            "error" => {
                required_object(object, "error")?;
            }
            event if is_mcp_event(event) => {
                self.require_active_response()?;
            }
            other => return Err(RealtimeValidationError::UnsupportedEvent(other.to_owned())),
        }
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<(), RealtimeValidationError> {
        if self.response_requested || self.response_active {
            Err(RealtimeValidationError::InvalidLifecycle(
                "connection ended before response.done",
            ))
        } else {
            Ok(())
        }
    }

    fn require_active_response(&self) -> Result<(), RealtimeValidationError> {
        if self.response_active {
            Ok(())
        } else {
            Err(RealtimeValidationError::InvalidLifecycle(
                "response event requires an active response",
            ))
        }
    }
}

fn parse_object(payload: &[u8]) -> Result<Map<String, Value>, RealtimeValidationError> {
    match serde_json::from_slice(payload)? {
        Value::Object(object) => Ok(object),
        _ => Err(RealtimeValidationError::RootNotObject),
    }
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Map<String, Value>, RealtimeValidationError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or(RealtimeValidationError::InvalidField(field))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, RealtimeValidationError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(RealtimeValidationError::InvalidField(field))
}

fn optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<(), RealtimeValidationError> {
    if object
        .get(field)
        .is_some_and(|value| !value.is_null() && value.as_str().is_none_or(str::is_empty))
    {
        Err(RealtimeValidationError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn required_u64(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<u64, RealtimeValidationError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(RealtimeValidationError::InvalidField(field))
}

fn require_session(created: bool) -> Result<(), RealtimeValidationError> {
    if created {
        Ok(())
    } else {
        Err(RealtimeValidationError::InvalidLifecycle(
            "server event preceded session.created",
        ))
    }
}

fn is_response_progress_event(event: &str) -> bool {
    matches!(
        event,
        "response.content_part.added"
            | "response.content_part.done"
            | "response.function_call_arguments.delta"
            | "response.function_call_arguments.done"
            | "response.output_audio.delta"
            | "response.output_audio.done"
            | "response.output_audio_transcript.delta"
            | "response.output_audio_transcript.done"
            | "response.output_item.added"
            | "response.output_item.done"
            | "response.output_text.delta"
            | "response.output_text.done"
    )
}

fn validate_response_progress(
    event: &str,
    object: &Map<String, Value>,
) -> Result<(), RealtimeValidationError> {
    if event.ends_with(".delta") {
        let delta = required_string(object, "delta")?;
        if event == "response.output_audio.delta"
            && base64::engine::general_purpose::STANDARD
                .decode(delta)
                .is_err()
        {
            return Err(RealtimeValidationError::InvalidField("delta"));
        }
    }
    Ok(())
}

fn is_conversation_event(event: &str) -> bool {
    matches!(
        event,
        "conversation.item.added"
            | "conversation.item.created"
            | "conversation.item.deleted"
            | "conversation.item.done"
            | "conversation.item.input_audio_transcription.completed"
            | "conversation.item.input_audio_transcription.delta"
            | "conversation.item.input_audio_transcription.failed"
            | "conversation.item.input_audio_transcription.segment"
            | "conversation.item.retrieved"
            | "conversation.item.truncated"
    )
}

fn is_audio_buffer_event(event: &str) -> bool {
    matches!(
        event,
        "input_audio_buffer.cleared"
            | "input_audio_buffer.committed"
            | "input_audio_buffer.dtmf_event_received"
            | "input_audio_buffer.speech_started"
            | "input_audio_buffer.speech_stopped"
            | "input_audio_buffer.timeout_triggered"
            | "output_audio_buffer.started"
            | "output_audio_buffer.stopped"
            | "output_audio_buffer.cleared"
    )
}

fn is_mcp_event(event: &str) -> bool {
    matches!(
        event,
        "mcp_list_tools.in_progress"
            | "mcp_list_tools.completed"
            | "mcp_list_tools.failed"
            | "response.mcp_call_arguments.delta"
            | "response.mcp_call_arguments.done"
            | "response.mcp_call.in_progress"
            | "response.mcp_call.completed"
            | "response.mcp_call.failed"
    )
}

#[cfg(test)]
mod tests {
    use super::OpenAiRealtimeValidator;

    #[test]
    fn validates_audio_tool_interruption_and_terminal_lifecycle() {
        let mut validator = OpenAiRealtimeValidator::default();
        validator
            .validate_server(br#"{"type":"session.created","event_id":"e1","session":{}}"#)
            .unwrap();
        validator
            .validate_client(br#"{"type":"input_audio_buffer.append","audio":"AQI="}"#)
            .unwrap();
        validator
            .validate_client(br#"{"type":"input_audio_buffer.commit"}"#)
            .unwrap();
        validator
            .validate_client(br#"{"type":"response.create","response":{"tools":[]}}"#)
            .unwrap();
        validator
            .validate_server(br#"{"type":"response.created","event_id":"e2","response":{}}"#)
            .unwrap();
        validator
            .validate_server(br#"{"type":"response.function_call_arguments.delta","event_id":"e3","delta":"{}"}"#)
            .unwrap();
        validator
            .validate_client(br#"{"type":"response.cancel"}"#)
            .unwrap();
        validator
            .validate_client(br#"{"type":"output_audio_buffer.clear"}"#)
            .unwrap();
        validator
            .validate_server(
                br#"{"type":"response.done","event_id":"e4","response":{"status":"cancelled"}}"#,
            )
            .unwrap();
        validator.finish().unwrap();
    }

    #[test]
    fn rejects_events_outside_the_documented_lifecycle() {
        let mut validator = OpenAiRealtimeValidator::default();
        assert!(validator
            .validate_client(br#"{"type":"response.cancel"}"#)
            .is_err());
        assert!(validator
            .validate_server(
                br#"{"type":"response.output_text.delta","event_id":"e","delta":"late"}"#
            )
            .is_err());
        assert!(validator
            .validate_client(br#"{"type":"input_audio_buffer.append","audio":"not base64"}"#)
            .is_err());
        validator
            .validate_client(br#"{"type":"response.create"}"#)
            .unwrap();
        assert!(validator.finish().is_err());
    }
}
