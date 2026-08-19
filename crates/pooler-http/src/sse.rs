//! Incremental Server-Sent Events framing.
//!
//! The parser owns only the bytes needed for the current line and event. It
//! does not assume that transport chunks line up with SSE records, and it
//! reports an unterminated final record instead of silently treating it as a
//! complete response.

use std::str;

use thiserror::Error;

/// Default maximum size of one SSE line, excluding its line ending.
pub const DEFAULT_SSE_MAX_LINE_BYTES: usize = 64 * 1024;
/// Default maximum size of one SSE record, including field line endings.
pub const DEFAULT_SSE_MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

/// Bounds applied while parsing or encoding one SSE stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SseLimits {
    /// Maximum bytes in one field line, excluding its line ending.
    pub max_line_bytes: usize,
    /// Maximum bytes in one record, including field line endings.
    pub max_event_bytes: usize,
}

impl SseLimits {
    /// Creates explicit SSE limits.
    #[must_use]
    pub const fn new(max_line_bytes: usize, max_event_bytes: usize) -> Self {
        Self {
            max_line_bytes,
            max_event_bytes,
        }
    }
}

impl Default for SseLimits {
    fn default() -> Self {
        Self::new(DEFAULT_SSE_MAX_LINE_BYTES, DEFAULT_SSE_MAX_EVENT_BYTES)
    }
}

/// One dispatched SSE record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SseEvent {
    /// Optional event type. None represents the default message type.
    pub event: Option<String>,
    /// Event data after joining multiple data lines with newlines.
    pub data: String,
    /// Last event ID in effect when this record was dispatched.
    pub id: Option<String>,
}

impl SseEvent {
    /// Creates a default-type event with the supplied data.
    #[must_use]
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            event: None,
            data: data.into(),
            id: None,
        }
    }

    /// Sets the event type.
    #[must_use]
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Sets the event ID.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Returns whether this is the conventional OpenAI-style stream sentinel.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.event.is_none() && self.data == "[DONE]"
    }
}

/// Errors raised while parsing or encoding bounded SSE data.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SseError {
    /// A field line exceeded the configured bound.
    #[error("SSE line exceeds the {limit} byte limit (observed at least {observed} bytes)")]
    LineTooLarge { limit: usize, observed: usize },
    /// A record exceeded the configured bound.
    #[error("SSE event exceeds the {limit} byte limit (observed at least {observed} bytes)")]
    EventTooLarge { limit: usize, observed: usize },
    /// The stream contained bytes that are not valid UTF-8.
    #[error("SSE stream contains invalid UTF-8")]
    InvalidUtf8,
    /// The input ended before a record delimiter was received.
    #[error("SSE stream ended with an incomplete event ({bytes} bytes pending)")]
    Incomplete { bytes: usize },
    /// An encoded field would inject a new SSE line.
    #[error("SSE {field} field contains a line break")]
    InvalidField { field: &'static str },
}

/// Incremental SSE record parser.
#[derive(Debug)]
pub struct SseParser {
    limits: SseLimits,
    line: Vec<u8>,
    pending_cr: bool,
    event_name: Option<String>,
    data: String,
    has_data: bool,
    last_event_id: Option<String>,
    event_bytes: usize,
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SseParser {
    /// Creates a parser with the default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(SseLimits::default())
    }

    /// Creates a parser with explicit bounds.
    #[must_use]
    pub fn with_limits(limits: SseLimits) -> Self {
        Self {
            limits,
            line: Vec::new(),
            pending_cr: false,
            event_name: None,
            data: String::new(),
            has_data: false,
            last_event_id: None,
            event_bytes: 0,
        }
    }

    /// Returns the parser's configured bounds.
    #[must_use]
    pub const fn limits(&self) -> SseLimits {
        self.limits
    }

    /// Feeds one arbitrary transport chunk and returns records completed by it.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        let mut events = Vec::new();
        for &byte in chunk {
            if self.pending_cr {
                self.pending_cr = false;
                let line_ending_bytes = if byte == b'\n' { 2 } else { 1 };
                self.finish_line(&mut events, line_ending_bytes)?;
                if byte == b'\n' {
                    continue;
                }
            }

            match byte {
                b'\r' => self.pending_cr = true,
                b'\n' => self.finish_line(&mut events, 1)?,
                byte => self.push_line_byte(byte)?,
            }
        }
        Ok(events)
    }

    /// Signals transport EOF. An unfinished field or record is an error.
    pub fn finish(&mut self) -> Result<Vec<SseEvent>, SseError> {
        let mut events = Vec::new();
        if self.pending_cr {
            self.pending_cr = false;
            self.finish_line(&mut events, 1)?;
        }
        if !self.line.is_empty() {
            return Err(SseError::Incomplete {
                bytes: self.pending_bytes(),
            });
        }
        if self.has_data || self.event_name.is_some() || self.event_bytes != 0 {
            return Err(SseError::Incomplete {
                bytes: self.pending_bytes(),
            });
        }
        Ok(events)
    }

    fn push_line_byte(&mut self, byte: u8) -> Result<(), SseError> {
        let observed = self.line.len().saturating_add(1);
        if observed > self.limits.max_line_bytes {
            return Err(SseError::LineTooLarge {
                limit: self.limits.max_line_bytes,
                observed,
            });
        }
        self.line.push(byte);
        Ok(())
    }

    fn finish_line(
        &mut self,
        events: &mut Vec<SseEvent>,
        line_ending_bytes: usize,
    ) -> Result<(), SseError> {
        let line = str::from_utf8(&self.line)
            .map_err(|_| SseError::InvalidUtf8)?
            .to_owned();
        if !line.starts_with(':') {
            let line_bytes = self.line.len().saturating_add(line_ending_bytes);
            self.event_bytes = self.event_bytes.saturating_add(line_bytes);
            if self.event_bytes > self.limits.max_event_bytes {
                return Err(SseError::EventTooLarge {
                    limit: self.limits.max_event_bytes,
                    observed: self.event_bytes,
                });
            }
        }
        self.process_line(&line, events);
        self.line.clear();
        Ok(())
    }

    fn process_line(&mut self, line: &str, events: &mut Vec<SseEvent>) {
        if line.is_empty() {
            if self.has_data {
                let data = self.data.strip_suffix('\n').unwrap_or_default().to_owned();
                events.push(SseEvent {
                    event: self.event_name.take().filter(|event| !event.is_empty()),
                    data,
                    id: self.last_event_id.clone(),
                });
            } else {
                self.event_name = None;
            }
            self.data.clear();
            self.has_data = false;
            self.event_bytes = 0;
            return;
        }

        if line.starts_with(':') {
            return;
        }

        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => self.event_name = Some(value.to_owned()),
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            "id" => {
                if !value.contains('\0') {
                    self.last_event_id = Some(value.to_owned());
                }
            }
            // retry affects a browser client's reconnection policy, not the
            // dispatched record. Other fields are intentionally ignored by SSE.
            _ => {}
        }
    }

    fn pending_bytes(&self) -> usize {
        self.line
            .len()
            .saturating_add(self.data.len())
            .saturating_add(self.event_bytes)
    }
}

/// Deterministic SSE record encoder.
#[derive(Clone, Copy, Debug)]
pub struct SseEncoder {
    limits: SseLimits,
}

impl Default for SseEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SseEncoder {
    /// Creates an encoder with the default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(SseLimits::default())
    }

    /// Creates an encoder with explicit bounds.
    #[must_use]
    pub const fn with_limits(limits: SseLimits) -> Self {
        Self { limits }
    }

    /// Encodes one event, including its terminating blank line.
    pub fn encode(&self, event: &SseEvent) -> Result<Vec<u8>, SseError> {
        let mut output = Vec::new();
        if let Some(event_name) = event.event.as_deref() {
            push_field(&mut output, "event", event_name, self.limits)?;
        }
        if let Some(id) = event.id.as_deref() {
            push_field(&mut output, "id", id, self.limits)?;
        }

        push_data_lines(&mut output, &event.data, self.limits)?;
        push_line(&mut output, b"", self.limits)?;
        Ok(output)
    }
}

fn push_field(
    output: &mut Vec<u8>,
    field: &'static str,
    value: &str,
    limits: SseLimits,
) -> Result<(), SseError> {
    if value.as_bytes().contains(&b'\r') || value.as_bytes().contains(&b'\n') {
        return Err(SseError::InvalidField { field });
    }
    let mut line = Vec::with_capacity(field.len() + value.len() + 1);
    line.extend_from_slice(field.as_bytes());
    line.extend_from_slice(b":");
    if value.as_bytes().first() == Some(&b' ') {
        line.push(b' ');
    }
    line.extend_from_slice(value.as_bytes());
    push_line(output, &line, limits)
}

fn push_data_lines(output: &mut Vec<u8>, data: &str, limits: SseLimits) -> Result<(), SseError> {
    let bytes = data.as_bytes();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\r' && bytes[index] != b'\n' {
            index += 1;
            continue;
        }
        push_data_line(output, &bytes[start..index], limits)?;
        if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            index += 1;
        }
        index += 1;
        start = index;
    }
    push_data_line(output, &bytes[start..], limits)
}

fn push_data_line(output: &mut Vec<u8>, data: &[u8], limits: SseLimits) -> Result<(), SseError> {
    let mut line = Vec::with_capacity(data.len() + 6);
    line.extend_from_slice(b"data:");
    if data.first() == Some(&b' ') {
        line.push(b' ');
    }
    line.extend_from_slice(data);
    push_line(output, &line, limits)
}

fn push_line(output: &mut Vec<u8>, line: &[u8], limits: SseLimits) -> Result<(), SseError> {
    if line.len() > limits.max_line_bytes {
        return Err(SseError::LineTooLarge {
            limit: limits.max_line_bytes,
            observed: line.len(),
        });
    }
    let observed = output.len().saturating_add(line.len()).saturating_add(1);
    if observed > limits.max_event_bytes {
        return Err(SseError::EventTooLarge {
            limit: limits.max_event_bytes,
            observed,
        });
    }
    output.extend_from_slice(line);
    output.push(b'\n');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SseEncoder, SseError, SseEvent, SseLimits, SseParser};

    #[test]
    fn parses_fragmented_crlf_multiline_records_and_comments() {
        let mut parser = SseParser::with_limits(SseLimits::new(32, 128));
        assert!(parser.feed(b": keep").unwrap().is_empty());
        assert!(parser.feed(b"alive\r").unwrap().is_empty());
        assert!(parser
            .feed(b"\nevent: message\r\ndata: hel")
            .unwrap()
            .is_empty());
        assert!(parser
            .feed(b"lo\r\ndata: world\r\nid: 7\r\n\r")
            .unwrap()
            .is_empty());
        let events = parser.feed(b"\n").unwrap();
        assert_eq!(
            events,
            vec![SseEvent::new("hello\nworld")
                .with_event("message")
                .with_id("7")]
        );
        assert!(parser.finish().unwrap().is_empty());
    }

    #[test]
    fn parses_lf_records_and_preserves_ids_across_events() {
        let mut parser = SseParser::new();
        let events = parser
            .feed(b"id: first\ndata: one\n\ndata: two\n\nid: third\n\n")
            .unwrap();
        assert_eq!(
            events,
            vec![
                SseEvent::new("one").with_id("first"),
                SseEvent::new("two").with_id("first")
            ]
        );
        assert!(parser.finish().unwrap().is_empty());
    }

    #[test]
    fn accepts_utf8_code_points_split_across_transport_chunks() {
        let mut parser = SseParser::new();
        assert!(parser.feed(b"data: \xc3").unwrap().is_empty());
        assert_eq!(parser.feed(b"\xa9\n\n").unwrap(), vec![SseEvent::new("é")]);
        assert!(parser.finish().unwrap().is_empty());
    }

    #[test]
    fn eof_rejects_partial_line_and_unterminated_event() {
        let mut partial_line = SseParser::new();
        partial_line.feed(b"data: partial").unwrap();
        assert!(matches!(
            partial_line.finish(),
            Err(SseError::Incomplete { .. })
        ));

        let mut partial_event = SseParser::new();
        partial_event.feed(b"data: complete-line\n").unwrap();
        assert!(matches!(
            partial_event.finish(),
            Err(SseError::Incomplete { .. })
        ));
    }

    #[test]
    fn comments_can_end_a_stream_without_dispatching_an_event() {
        let mut parser = SseParser::new();
        assert!(parser.feed(b": heartbeat\n").unwrap().is_empty());
        assert!(parser.finish().unwrap().is_empty());
    }

    #[test]
    fn enforces_line_and_event_limits() {
        let mut line_limited = SseParser::with_limits(SseLimits::new(5, 128));
        assert_eq!(
            line_limited.feed(b"data: x\n"),
            Err(SseError::LineTooLarge {
                limit: 5,
                observed: 6
            })
        );

        let mut event_limited = SseParser::with_limits(SseLimits::new(32, 8));
        assert!(matches!(
            event_limited.feed(b"data: x\n\n"),
            Err(SseError::EventTooLarge {
                limit: 8,
                observed: 9
            })
        ));

        let mut crlf_event_limited = SseParser::with_limits(SseLimits::new(32, 10));
        assert!(matches!(
            crlf_event_limited.feed(b"data: x\r\n\r\n"),
            Err(SseError::EventTooLarge {
                limit: 10,
                observed: 11
            })
        ));
    }

    #[test]
    fn rejects_invalid_utf8_and_encoder_line_injection() {
        let mut parser = SseParser::new();
        assert_eq!(parser.feed(b"data: \xff\n"), Err(SseError::InvalidUtf8));

        let encoder = SseEncoder::new();
        assert_eq!(
            encoder.encode(&SseEvent::new("x").with_event("bad\nevent")),
            Err(SseError::InvalidField { field: "event" })
        );
    }

    #[test]
    fn round_trips_multiline_data_and_done_sentinel() {
        let event = SseEvent::new("first\nsecond\r\nthird").with_id("id-1");
        let normalized = SseEvent::new("first\nsecond\nthird").with_id("id-1");
        let encoded = SseEncoder::new().encode(&event).unwrap();
        assert_eq!(encoded, b"id:id-1\ndata:first\ndata:second\ndata:third\n\n");

        let mut parser = SseParser::new();
        let mut parsed = parser.feed(&encoded).unwrap();
        assert!(parser.finish().unwrap().is_empty());
        assert_eq!(parsed.remove(0), normalized);

        let done = SseEvent::new("[DONE]");
        assert!(done.is_done());
        let done_bytes = SseEncoder::new().encode(&done).unwrap();
        assert_eq!(done_bytes, b"data:[DONE]\n\n");
    }

    #[test]
    fn round_trips_values_that_begin_with_a_space() {
        let event = SseEvent::new(" first").with_event(" custom").with_id(" id");
        let encoded = SseEncoder::new().encode(&event).unwrap();
        assert_eq!(encoded, b"event:  custom\nid:  id\ndata:  first\n\n");

        let mut parser = SseParser::new();
        assert_eq!(parser.feed(&encoded).unwrap(), vec![event]);
        assert!(parser.finish().unwrap().is_empty());
    }
}
