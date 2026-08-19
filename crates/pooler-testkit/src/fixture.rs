use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{Header, ScriptedChunk, ScriptedRequest, ScriptedResponse, ScriptedResult};

/// How a fixture compares two protocol representations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Equivalence {
    /// Every byte, header order, and chunk boundary is significant.
    #[default]
    ByteLevel,
    /// JSON object ordering and insignificant whitespace are ignored.
    JsonStructural,
    /// Protobuf messages are compared by their deterministic encoded bytes.
    ProtobufSemantic,
    /// Stream event ordering and payloads are compared after transport-only
    /// markers such as delays are normalized.
    EventSemantic,
}

impl Equivalence {
    /// Compatibility spelling for callers that call byte-level fixtures
    /// "byte-exact".
    #[allow(non_upper_case_globals)]
    pub const ByteExact: Self = Self::ByteLevel;

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ByteLevel => "byte_level",
            Self::JsonStructural => "json_structural",
            Self::ProtobufSemantic => "protobuf_semantic",
            Self::EventSemantic => "event_semantic",
        }
    }

    #[must_use]
    pub const fn ignores_transport_timing(self) -> bool {
        !matches!(self, Self::ByteLevel)
    }
}

/// Alias used by fixture runners that call the field an equivalence kind.
pub type EquivalenceKind = Equivalence;
/// Alias matching the wording in compatibility fixture metadata.
pub type FixtureEquivalence = Equivalence;

/// Metadata stored next to a sanitized compatibility fixture.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureMetadata {
    pub id: String,
    pub equivalence: Equivalence,
    #[serde(default)]
    pub intentional_corrections: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl FixtureMetadata {
    #[must_use]
    pub fn new(id: impl Into<String>, equivalence: Equivalence) -> Self {
        Self {
            id: id.into(),
            equivalence,
            intentional_corrections: Vec::new(),
            notes: None,
        }
    }

    #[must_use]
    pub fn correction(mut self, correction: impl Into<String>) -> Self {
        self.intentional_corrections.push(correction.into());
        self
    }

    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.notes = Some(note.into());
        self
    }
}

/// Expected health change attached to a fixture outcome.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ExpectedHealthMutation {
    #[default]
    None,
    CredentialCooldown {
        credential: String,
        duration_ms: u64,
    },
    ProviderCooldown {
        provider: String,
        duration_ms: u64,
    },
    ModelCooldown {
        model: String,
        duration_ms: u64,
    },
    Custom {
        scope: String,
        reason: String,
    },
}

/// A compact report captured by a fixture runner when semantic conversion is
/// involved.  The shape mirrors the protocol crate without coupling testkit to
/// one runtime representation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConversionReport {
    #[serde(default)]
    pub preserved_capabilities: Vec<String>,
    #[serde(default)]
    pub degraded_fields: Vec<String>,
    #[serde(default)]
    pub dropped_optional_fields: Vec<String>,
    #[serde(default)]
    pub unsupported_required_fields: Vec<String>,
    #[serde(default)]
    pub preserved_extensions: Vec<String>,
    #[serde(default)]
    pub rules_applied: Vec<String>,
}

impl ConversionReport {
    #[must_use]
    pub fn is_lossless(&self) -> bool {
        self.degraded_fields.is_empty()
            && self.dropped_optional_fields.is_empty()
            && self.unsupported_required_fields.is_empty()
    }
}

/// The complete sanitized record used by a golden or differential test.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Fixture {
    pub metadata: FixtureMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downstream_request: Option<ScriptedRequest>,
    #[serde(default)]
    pub extracted_fields: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_upstream_request: Option<ScriptedRequest>,
    #[serde(default)]
    pub upstream_script: Vec<ScriptedResult>,
    #[serde(default)]
    pub expected_downstream_chunks: Vec<ScriptedChunk>,
    #[serde(default)]
    pub conversion_report: ConversionReport,
    #[serde(default)]
    pub expected_health_mutation: ExpectedHealthMutation,
}

impl Fixture {
    #[must_use]
    pub fn new(id: impl Into<String>, equivalence: Equivalence) -> Self {
        Self {
            metadata: FixtureMetadata::new(id, equivalence),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_downstream_request(mut self, request: ScriptedRequest) -> Self {
        self.downstream_request = Some(request);
        self
    }

    #[must_use]
    pub fn with_expected_upstream_request(mut self, request: ScriptedRequest) -> Self {
        self.expected_upstream_request = Some(request);
        self
    }

    #[must_use]
    pub fn with_upstream_script<I>(mut self, script: I) -> Self
    where
        I: IntoIterator<Item = ScriptedResult>,
    {
        self.upstream_script = script.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_downstream_chunks<I>(mut self, chunks: I) -> Self
    where
        I: IntoIterator<Item = ScriptedChunk>,
    {
        self.expected_downstream_chunks = chunks.into_iter().collect();
        self
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        normalize_fixture(self)
    }

    #[must_use]
    pub fn compare(&self, actual: &Self) -> EquivalenceReport {
        compare_fixtures(self, actual)
    }
}

/// A structured, deterministic comparison result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EquivalenceReport {
    pub equivalent: bool,
    pub differences: Vec<String>,
}

impl EquivalenceReport {
    #[must_use]
    pub fn is_equivalent(&self) -> bool {
        self.equivalent
    }

    fn equal() -> Self {
        Self {
            equivalent: true,
            differences: Vec::new(),
        }
    }

    fn difference(path: impl Into<String>) -> Self {
        Self {
            equivalent: false,
            differences: vec![path.into()],
        }
    }

    fn append(&mut self, mut other: Self) {
        if !other.equivalent {
            self.equivalent = false;
            self.differences.append(&mut other.differences);
        }
    }
}

/// Errors returned when a JSON body cannot be normalized.
#[derive(Debug, Error)]
pub enum NormalizationError {
    #[error("invalid JSON fixture body: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

/// Normalize a JSON body into compact, recursively key-sorted bytes.
///
/// # Errors
///
/// Returns [`NormalizationError::InvalidJson`] when `input` is not valid JSON.
pub fn normalize_json(input: &[u8]) -> Result<Vec<u8>, NormalizationError> {
    let value: Value = serde_json::from_slice(input)?;
    serde_json::to_vec(&normalize_json_value(value)).map_err(NormalizationError::from)
}

/// Recursively normalize object key ordering while preserving arrays and scalar
/// values exactly.
#[must_use]
pub fn normalize_json_value(value: Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.into_iter().map(normalize_json_value).collect())
        }
        Value::Object(values) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in values {
                sorted.insert(key, normalize_json_value(value));
            }
            let mut object = Map::new();
            for (key, value) in sorted {
                object.insert(key, value);
            }
            Value::Object(object)
        }
        scalar => scalar,
    }
}

/// Lowercase and trim header names, trim values, and sort by name/value.
#[must_use]
pub fn normalize_headers(headers: &[Header]) -> Vec<Header> {
    let mut normalized: Vec<_> = headers
        .iter()
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    normalized.sort_unstable();
    normalized
}

/// Normalize a request according to body content type while retaining method,
/// URI, and normalized headers.
#[must_use]
pub fn normalize_request(request: &ScriptedRequest) -> ScriptedRequest {
    let mut normalized = request.clone();
    normalized.method = normalized.method.to_ascii_uppercase();
    normalized.headers = normalize_headers(&normalized.headers);
    if normalized.headers.iter().any(|(name, value)| {
        name == "content-type" && value.to_ascii_lowercase().starts_with("application/json")
    }) {
        if let Ok(body) = normalize_json(&normalized.body) {
            normalized.body = body;
        }
    }
    normalized
}

/// Normalize stream events by removing timing markers and making SSE line
/// endings deterministic.
#[must_use]
pub fn normalize_chunks(chunks: &[ScriptedChunk]) -> Vec<ScriptedChunk> {
    chunks
        .iter()
        .filter_map(|chunk| match chunk {
            ScriptedChunk::Delay(_) => None,
            ScriptedChunk::Sse { event, data } => Some(ScriptedChunk::Sse {
                event: event.clone(),
                data: data.replace("\r\n", "\n").replace('\r', "\n"),
            }),
            other => Some(other.clone()),
        })
        .collect()
}

/// Normalize every comparable field in a fixture.
#[must_use]
pub fn normalize_fixture(fixture: &Fixture) -> Fixture {
    let mut normalized = fixture.clone();
    normalized.downstream_request = normalized
        .downstream_request
        .as_ref()
        .map(normalize_request);
    normalized.expected_upstream_request = normalized
        .expected_upstream_request
        .as_ref()
        .map(normalize_request);
    normalized.expected_downstream_chunks =
        normalize_chunks(&normalized.expected_downstream_chunks);
    normalized.upstream_script = normalized
        .upstream_script
        .iter()
        .map(normalize_result)
        .collect();
    normalized
}

fn normalize_result(result: &ScriptedResult) -> ScriptedResult {
    match result {
        ScriptedResult::Response(response) => ScriptedResult::Response(ScriptedResponse {
            status: response.status,
            headers: normalize_headers(&response.headers),
            chunks: normalize_chunks(&response.chunks),
        }),
        other => other.clone(),
    }
}

fn compare_upstream_script(
    expected: &[ScriptedResult],
    actual: &[ScriptedResult],
    equivalence: Equivalence,
) -> EquivalenceReport {
    let expected = if matches!(equivalence, Equivalence::ByteLevel) {
        expected.to_vec()
    } else {
        expected.iter().map(normalize_result).collect()
    };
    let actual = if matches!(equivalence, Equivalence::ByteLevel) {
        actual.to_vec()
    } else {
        actual.iter().map(normalize_result).collect()
    };

    if expected == actual {
        EquivalenceReport::equal()
    } else {
        EquivalenceReport::difference("upstream_script")
    }
}

/// Compare two requests using the selected equivalence relation.
#[must_use]
pub fn compare_requests(
    expected: &ScriptedRequest,
    actual: &ScriptedRequest,
    equivalence: Equivalence,
) -> EquivalenceReport {
    match equivalence {
        Equivalence::ByteLevel => {
            if expected == actual {
                EquivalenceReport::equal()
            } else {
                EquivalenceReport::difference("request")
            }
        }
        Equivalence::JsonStructural | Equivalence::EventSemantic => {
            if normalize_request(expected) == normalize_request(actual) {
                EquivalenceReport::equal()
            } else {
                EquivalenceReport::difference("request")
            }
        }
        Equivalence::ProtobufSemantic => {
            // Protobuf field order is already encoded by the deterministic
            // fixture writer.  The testkit intentionally does not depend on a
            // descriptor registry, so wire bytes are compared directly.
            if expected.method == actual.method
                && expected.uri == actual.uri
                && normalize_headers(&expected.headers) == normalize_headers(&actual.headers)
                && expected.body == actual.body
            {
                EquivalenceReport::equal()
            } else {
                EquivalenceReport::difference("request")
            }
        }
    }
}

/// Compare two scripted responses, ignoring only differences permitted by the
/// selected equivalence relation.
#[must_use]
pub fn compare_responses(
    expected: &ScriptedResponse,
    actual: &ScriptedResponse,
    equivalence: Equivalence,
) -> EquivalenceReport {
    let mut report = EquivalenceReport::equal();
    if expected.status != actual.status {
        report.append(EquivalenceReport::difference("response.status"));
    }
    if match equivalence {
        Equivalence::ByteLevel => expected.headers != actual.headers,
        _ => normalize_headers(&expected.headers) != normalize_headers(&actual.headers),
    } {
        report.append(EquivalenceReport::difference("response.headers"));
    }
    let expected_chunks = if matches!(equivalence, Equivalence::ByteLevel) {
        expected.chunks.clone()
    } else {
        normalize_chunks(&expected.chunks)
    };
    let actual_chunks = if matches!(equivalence, Equivalence::ByteLevel) {
        actual.chunks.clone()
    } else {
        normalize_chunks(&actual.chunks)
    };
    if matches!(equivalence, Equivalence::JsonStructural) {
        if !json_chunks_equal(&expected_chunks, &actual_chunks) {
            report.append(EquivalenceReport::difference("response.chunks"));
        }
    } else if expected_chunks != actual_chunks {
        report.append(EquivalenceReport::difference("response.chunks"));
    }
    report
}

fn json_chunks_equal(expected: &[ScriptedChunk], actual: &[ScriptedChunk]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .all(|(left, right)| match (left, right) {
            (ScriptedChunk::Bytes(left), ScriptedChunk::Bytes(right)) => {
                match (normalize_json(left), normalize_json(right)) {
                    (Ok(left), Ok(right)) => left == right,
                    _ => left == right,
                }
            }
            (ScriptedChunk::Text(left), ScriptedChunk::Text(right)) => {
                match (
                    normalize_json(left.as_bytes()),
                    normalize_json(right.as_bytes()),
                ) {
                    (Ok(left), Ok(right)) => left == right,
                    _ => left == right,
                }
            }
            (left, right) => left == right,
        })
}

/// Compare the request and expected stream fields of two fixtures.
#[must_use]
pub fn compare_fixtures(expected: &Fixture, actual: &Fixture) -> EquivalenceReport {
    let equivalence = expected.metadata.equivalence;
    let mut report = EquivalenceReport::equal();
    if expected.metadata.id != actual.metadata.id {
        report.append(EquivalenceReport::difference("metadata.id"));
    }
    if equivalence != actual.metadata.equivalence {
        report.append(EquivalenceReport::difference("metadata.equivalence"));
    }
    match (&expected.downstream_request, &actual.downstream_request) {
        (Some(left), Some(right)) => report.append(compare_requests(left, right, equivalence)),
        (None, None) => {}
        _ => report.append(EquivalenceReport::difference("downstream_request")),
    }
    if expected.extracted_fields != actual.extracted_fields {
        report.append(EquivalenceReport::difference("extracted_fields"));
    }
    match (
        &expected.expected_upstream_request,
        &actual.expected_upstream_request,
    ) {
        (Some(left), Some(right)) => report.append(compare_requests(left, right, equivalence)),
        (None, None) => {}
        _ => report.append(EquivalenceReport::difference("expected_upstream_request")),
    }
    report.append(compare_upstream_script(
        &expected.upstream_script,
        &actual.upstream_script,
        equivalence,
    ));
    let expected_response = ScriptedResponse {
        status: 200,
        headers: Vec::new(),
        chunks: expected.expected_downstream_chunks.clone(),
    };
    let actual_response = ScriptedResponse {
        status: 200,
        headers: Vec::new(),
        chunks: actual.expected_downstream_chunks.clone(),
    };
    report.append(compare_responses(
        &expected_response,
        &actual_response,
        equivalence,
    ));
    if expected.conversion_report != actual.conversion_report {
        report.append(EquivalenceReport::difference("conversion_report"));
    }
    if expected.expected_health_mutation != actual.expected_health_mutation {
        report.append(EquivalenceReport::difference("expected_health_mutation"));
    }
    report
}

/// Alias retained for callers that call health changes simply "mutations".
pub type HealthMutation = ExpectedHealthMutation;
