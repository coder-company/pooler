//! Bounded codecs for standalone media and multipart endpoint bodies.
//!
//! These codecs deliberately stop at the protocol boundary. They map raw
//! bytes and multipart form parts to the existing semantic media model, but
//! do not choose routes, providers, or endpoint paths.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::{ContentPart, MediaSource};

/// Default maximum accepted media body size: 32 MiB.
pub const DEFAULT_MEDIA_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Default maximum accepted size of one multipart part: 25 MiB.
pub const DEFAULT_MEDIA_MAX_PART_BYTES: usize = 25 * 1024 * 1024;
/// Default maximum number of multipart parts.
pub const DEFAULT_MEDIA_MAX_PARTS: usize = 32;
/// Default maximum size of one multipart part's header block.
pub const DEFAULT_MEDIA_MAX_HEADER_BYTES: usize = 8 * 1024;
/// Default maximum number of headers on one multipart part.
pub const DEFAULT_MEDIA_MAX_HEADERS_PER_PART: usize = 16;

/// Allocation and parser limits applied by the media codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaLimits {
    /// Maximum bytes accepted for the complete encoded body.
    pub max_body_bytes: usize,
    /// Maximum bytes accepted for one decoded multipart part.
    pub max_part_bytes: usize,
    /// Maximum number of decoded multipart parts.
    pub max_parts: usize,
    /// Maximum bytes accepted in one multipart header block.
    pub max_header_bytes: usize,
    /// Maximum number of headers accepted on one multipart part.
    pub max_headers_per_part: usize,
}

impl Default for MediaLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MEDIA_MAX_BODY_BYTES,
            max_part_bytes: DEFAULT_MEDIA_MAX_PART_BYTES,
            max_parts: DEFAULT_MEDIA_MAX_PARTS,
            max_header_bytes: DEFAULT_MEDIA_MAX_HEADER_BYTES,
            max_headers_per_part: DEFAULT_MEDIA_MAX_HEADERS_PER_PART,
        }
    }
}

/// One named multipart field represented by the semantic content model.
#[derive(Clone, Debug, PartialEq)]
pub struct MultipartMediaPart {
    /// `name` parameter from the part's `Content-Disposition` header.
    pub field_name: String,
    /// Optional `filename` parameter for a file attachment.
    ///
    /// Its presence classifies decoded bytes as [`ContentPart::File`], and it
    /// must match the name inside an encoded file part. Image and audio parts
    /// have no filename because their semantic variants cannot retain one.
    pub filename: Option<String>,
    /// Text, image, audio, or file value.
    pub content: ContentPart,
}

impl MultipartMediaPart {
    /// Creates a named text form field.
    #[must_use]
    pub fn text(field_name: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            field_name: field_name.into(),
            filename: None,
            content: ContentPart::text(text),
        }
    }

    /// Creates a named media form field.
    #[must_use]
    pub fn media(
        field_name: impl Into<String>,
        filename: Option<String>,
        content: ContentPart,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            filename,
            content,
        }
    }
}

/// A decoded multipart form whose field names are unique.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecodedMultipartMedia {
    /// Parts in wire order.
    pub parts: Vec<MultipartMediaPart>,
}

/// A raw binary media body and the headers needed to send it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedBinaryMedia {
    /// Body bytes.
    pub body: Vec<u8>,
    /// Validated `Content-Type` header value.
    pub media_type: String,
    /// Optional filename retained from a semantic file part.
    pub filename: Option<String>,
}

/// An encoded `multipart/form-data` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedMultipartMedia {
    /// Complete multipart body bytes.
    pub body: Vec<u8>,
    /// `Content-Type` header value including the boundary parameter.
    pub content_type: String,
}

/// Errors returned by bounded media codecs.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MediaCodecError {
    /// The complete body exceeded its configured limit.
    #[error("media body exceeds the {limit} byte limit (observed {observed} bytes)")]
    BodyTooLarge {
        /// Configured byte limit.
        limit: usize,
        /// Observed body size.
        observed: usize,
    },
    /// One multipart part exceeded its configured limit.
    #[error("multipart part {part} exceeds the {limit} byte limit (observed {observed} bytes)")]
    PartTooLarge {
        /// Zero-based part index.
        part: usize,
        /// Configured byte limit.
        limit: usize,
        /// Observed part size.
        observed: usize,
    },
    /// A multipart body contained too many parts.
    #[error("multipart body exceeds the {limit} part limit")]
    TooManyParts {
        /// Configured part limit.
        limit: usize,
    },
    /// A multipart header block exceeded its configured limit.
    #[error("multipart part {part} headers exceed the {limit} byte limit")]
    HeadersTooLarge {
        /// Zero-based part index.
        part: usize,
        /// Configured byte limit.
        limit: usize,
    },
    /// A multipart part contained too many headers.
    #[error("multipart part {part} exceeds the {limit} header limit")]
    TooManyHeaders {
        /// Zero-based part index.
        part: usize,
        /// Configured header count limit.
        limit: usize,
    },
    /// One standalone header value exceeded the configured header bound.
    #[error("media header value exceeds the {limit} byte limit (observed {observed} bytes)")]
    HeaderValueTooLarge {
        /// Configured byte limit.
        limit: usize,
        /// Observed header value size.
        observed: usize,
    },
    /// A media type was missing, ambiguous, or malformed.
    #[error("invalid media content type")]
    InvalidContentType,
    /// A multipart boundary was missing or malformed.
    #[error("invalid multipart boundary")]
    InvalidBoundary,
    /// Multipart framing was incomplete or malformed.
    #[error("malformed multipart body")]
    MalformedMultipart,
    /// A required multipart header was absent.
    #[error("multipart part {part} is missing header `{header}`")]
    MissingHeader {
        /// Zero-based part index.
        part: usize,
        /// Required lower-case header name.
        header: &'static str,
    },
    /// A header occurred more than once on one part.
    #[error("multipart part {part} repeats header `{header}`")]
    DuplicateHeader {
        /// Zero-based part index.
        part: usize,
        /// Repeated lower-case header name.
        header: String,
    },
    /// A content-disposition parameter occurred more than once.
    #[error("multipart part {part} repeats content-disposition parameter `{parameter}`")]
    DuplicateDispositionParameter {
        /// Zero-based part index.
        part: usize,
        /// Repeated lower-case parameter name.
        parameter: String,
    },
    /// A multipart field name occurred more than once.
    #[error("multipart field name `{name}` occurs more than once")]
    DuplicateFieldName {
        /// Repeated field name.
        name: String,
    },
    /// A multipart header is not represented by this lossless codec.
    #[error("multipart part {part} uses unsupported header `{header}`")]
    UnsupportedHeader {
        /// Zero-based part index.
        part: usize,
        /// Unsupported lower-case header name.
        header: String,
    },
    /// A content-disposition parameter is not represented by this codec.
    #[error("multipart part {part} uses unsupported content-disposition parameter `{parameter}`")]
    UnsupportedDispositionParameter {
        /// Zero-based part index.
        part: usize,
        /// Unsupported lower-case parameter name.
        parameter: String,
    },
    /// A multipart field had an empty or unsafe name or filename.
    #[error("multipart part {part} has an invalid {field}")]
    InvalidDispositionValue {
        /// Zero-based part index.
        part: usize,
        /// Invalid parameter name.
        field: &'static str,
    },
    /// A text field was not valid UTF-8.
    #[error("multipart text part {part} is not valid UTF-8")]
    InvalidText {
        /// Zero-based part index.
        part: usize,
    },
    /// A semantic media body used a URI instead of inline bytes.
    #[error("binary media encoding requires inline bytes")]
    NonInlineSource,
    /// The semantic content kind cannot be represented by a raw or multipart body.
    #[error("unsupported semantic content for media encoding")]
    UnsupportedContent,
    /// The wrapper filename conflicts with the semantic file filename.
    #[error("multipart filename metadata is ambiguous")]
    ConflictingFilename,
    /// The semantic content kind conflicts with its media type.
    #[error("semantic media kind does not match its content type")]
    MediaTypeMismatch,
    /// A multipart boundary occurs as a delimiter line inside part bytes.
    #[error("multipart boundary collides with part {part} bytes")]
    BoundaryCollision {
        /// Zero-based part index.
        part: usize,
    },
}

/// Stateless entry points for bounded media conversion.
pub struct MediaCodec;

impl MediaCodec {
    /// Decodes a raw image, audio, or file body into an inline semantic part.
    pub fn decode_binary(
        input: &[u8],
        media_type: &str,
        filename: Option<&str>,
        limits: MediaLimits,
    ) -> Result<ContentPart, MediaCodecError> {
        decode_binary_media(input, media_type, filename, limits)
    }

    /// Encodes one inline semantic image, audio, or file as a raw body.
    pub fn encode_binary(
        part: &ContentPart,
        limits: MediaLimits,
    ) -> Result<EncodedBinaryMedia, MediaCodecError> {
        encode_binary_media(part, limits)
    }

    /// Decodes a complete `multipart/form-data` body.
    pub fn decode_multipart(
        input: &[u8],
        content_type: &str,
        limits: MediaLimits,
    ) -> Result<DecodedMultipartMedia, MediaCodecError> {
        decode_multipart_media(input, content_type, limits)
    }

    /// Encodes semantic form fields as a complete `multipart/form-data` body.
    pub fn encode_multipart(
        parts: &[MultipartMediaPart],
        boundary: &str,
        limits: MediaLimits,
    ) -> Result<EncodedMultipartMedia, MediaCodecError> {
        encode_multipart_media(parts, boundary, limits)
    }
}

/// Decode a bounded raw media body.
pub fn decode_binary_media(
    input: &[u8],
    media_type: &str,
    filename: Option<&str>,
    limits: MediaLimits,
) -> Result<ContentPart, MediaCodecError> {
    enforce_body_limit(input.len(), limits)?;
    enforce_header_value_limit(media_type, limits)?;
    let essence = validate_media_type(media_type)?;
    if let Some(filename) = filename {
        enforce_header_value_limit(filename, limits)?;
        validate_disposition_value(filename, 0, "filename")?;
    }
    Ok(part_from_bytes(
        media_type.trim().to_owned(),
        essence,
        filename.map(str::to_owned),
        input.to_vec(),
    ))
}

/// Encode a bounded inline semantic media part as a raw body.
pub fn encode_binary_media(
    part: &ContentPart,
    limits: MediaLimits,
) -> Result<EncodedBinaryMedia, MediaCodecError> {
    let (media_type, source, filename) = media_fields(part)?;
    enforce_header_value_limit(media_type, limits)?;
    let essence = validate_media_type(media_type)?;
    validate_media_kind(part, &essence, filename)?;
    if let Some(filename) = filename {
        enforce_header_value_limit(filename, limits)?;
        validate_disposition_value(filename, 0, "filename")?;
    }
    let MediaSource::Inline(body) = source else {
        return Err(MediaCodecError::NonInlineSource);
    };
    enforce_body_limit(body.len(), limits)?;
    Ok(EncodedBinaryMedia {
        body: body.clone(),
        media_type: media_type.trim().to_owned(),
        filename: filename.map(str::to_owned),
    })
}

/// Decode a bounded `multipart/form-data` body into named semantic parts.
pub fn decode_multipart_media(
    input: &[u8],
    content_type: &str,
    limits: MediaLimits,
) -> Result<DecodedMultipartMedia, MediaCodecError> {
    enforce_body_limit(input.len(), limits)?;
    enforce_header_value_limit(content_type, limits)?;
    let boundary = multipart_boundary(content_type)?;
    let delimiter = [b"--".as_slice(), boundary.as_bytes()].concat();
    if !input.starts_with(&delimiter) {
        return Err(MediaCodecError::MalformedMultipart);
    }

    let mut cursor = delimiter.len();
    if input.get(cursor..cursor.saturating_add(2)) == Some(b"--") {
        cursor += 2;
        require_terminal_suffix(&input[cursor..])?;
        return Ok(DecodedMultipartMedia::default());
    }
    if input.get(cursor..cursor.saturating_add(2)) != Some(b"\r\n") {
        return Err(MediaCodecError::MalformedMultipart);
    }
    cursor += 2;

    let marker = [b"\r\n--".as_slice(), boundary.as_bytes()].concat();
    let mut parts = Vec::new();
    let mut names = BTreeSet::new();
    loop {
        let part_index = parts.len();
        if part_index >= limits.max_parts {
            return Err(MediaCodecError::TooManyParts {
                limit: limits.max_parts,
            });
        }

        let header_end = find_header_end(&input[cursor..], part_index, limits)?;
        let headers = parse_part_headers(&input[cursor..cursor + header_end], part_index, limits)?;
        cursor += header_end + 4;

        let (body_end, after_marker) = find_next_boundary(input, cursor, &marker)?;
        let part_body = &input[cursor..body_end];
        if part_body.len() > limits.max_part_bytes {
            return Err(MediaCodecError::PartTooLarge {
                part: part_index,
                limit: limits.max_part_bytes,
                observed: part_body.len(),
            });
        }
        let (field_name, filename) = parse_content_disposition(&headers, part_index)?;
        if !names.insert(field_name.clone()) {
            return Err(MediaCodecError::DuplicateFieldName { name: field_name });
        }

        let content = if let Some(media_type) = headers.get("content-type") {
            let essence = validate_media_type(media_type)?;
            if filename.is_none() && essence.starts_with("text/") {
                decode_text_part(part_body, part_index)?
            } else {
                part_from_bytes(
                    media_type.trim().to_owned(),
                    essence,
                    filename.clone(),
                    part_body.to_vec(),
                )
            }
        } else if filename.is_some() {
            part_from_bytes(
                "application/octet-stream".to_owned(),
                "application/octet-stream".to_owned(),
                filename.clone(),
                part_body.to_vec(),
            )
        } else {
            decode_text_part(part_body, part_index)?
        };
        parts.push(MultipartMediaPart {
            field_name,
            filename,
            content,
        });

        cursor = after_marker;
        if input.get(cursor..cursor.saturating_add(2)) == Some(b"--") {
            cursor += 2;
            require_terminal_suffix(&input[cursor..])?;
            break;
        }
        if input.get(cursor..cursor.saturating_add(2)) != Some(b"\r\n") {
            return Err(MediaCodecError::MalformedMultipart);
        }
        cursor += 2;
    }

    Ok(DecodedMultipartMedia { parts })
}

/// Encode named semantic parts as bounded `multipart/form-data` bytes.
pub fn encode_multipart_media(
    parts: &[MultipartMediaPart],
    boundary: &str,
    limits: MediaLimits,
) -> Result<EncodedMultipartMedia, MediaCodecError> {
    validate_boundary(boundary)?;
    let content_type = format!("multipart/form-data; boundary=\"{boundary}\"");
    enforce_header_value_limit(&content_type, limits)?;
    if parts.len() > limits.max_parts {
        return Err(MediaCodecError::TooManyParts {
            limit: limits.max_parts,
        });
    }

    let mut names = BTreeSet::new();
    let mut body = Vec::new();
    let embedded_marker = [b"\r\n--".as_slice(), boundary.as_bytes()].concat();
    for (part_index, part) in parts.iter().enumerate() {
        validate_disposition_value(&part.field_name, part_index, "name")?;
        if !names.insert(part.field_name.as_str()) {
            return Err(MediaCodecError::DuplicateFieldName {
                name: part.field_name.clone(),
            });
        }

        let mut filename = part.filename.as_deref();
        let (part_body, media_type) = match &part.content {
            ContentPart::Text { text } => {
                if filename.is_some() {
                    return Err(MediaCodecError::ConflictingFilename);
                }
                (text.as_bytes(), None)
            }
            ContentPart::Image {
                media_type,
                source,
                detail,
            } => {
                if detail.is_some() || filename.is_some() {
                    return Err(MediaCodecError::UnsupportedContent);
                }
                (inline_bytes(source)?, Some(media_type.as_str()))
            }
            ContentPart::Audio { media_type, source } => {
                if filename.is_some() {
                    return Err(MediaCodecError::UnsupportedContent);
                }
                (inline_bytes(source)?, Some(media_type.as_str()))
            }
            ContentPart::File {
                name,
                media_type,
                source,
            } => {
                if filename != name.as_deref() {
                    return Err(MediaCodecError::ConflictingFilename);
                }
                filename = name.as_deref();
                (inline_bytes(source)?, Some(media_type.as_str()))
            }
            ContentPart::Reasoning(_)
            | ContentPart::ToolCall(_)
            | ContentPart::ToolResult(_)
            | ContentPart::Provider { .. } => {
                return Err(MediaCodecError::UnsupportedContent);
            }
        };

        if part_body.len() > limits.max_part_bytes {
            return Err(MediaCodecError::PartTooLarge {
                part: part_index,
                limit: limits.max_part_bytes,
                observed: part_body.len(),
            });
        }
        if contains_boundary_line(part_body, &embedded_marker) {
            return Err(MediaCodecError::BoundaryCollision { part: part_index });
        }
        if let Some(filename) = filename {
            validate_disposition_value(filename, part_index, "filename")?;
        }
        if let Some(media_type) = media_type {
            enforce_header_value_limit(media_type, limits)?;
            let essence = validate_media_type(media_type)?;
            validate_media_kind(&part.content, &essence, filename)?;
        }

        let disposition_bytes = disposition_value_length(&part.field_name, filename);
        let mut header_bytes = "Content-Disposition: "
            .len()
            .saturating_add(disposition_bytes);
        let header_count = usize::from(media_type.is_some()) + 1;
        if header_count > limits.max_headers_per_part {
            return Err(MediaCodecError::TooManyHeaders {
                part: part_index,
                limit: limits.max_headers_per_part,
            });
        }
        if let Some(media_type) = media_type {
            header_bytes = header_bytes
                .saturating_add("\r\nContent-Type: ".len())
                .saturating_add(media_type.trim().len());
        }
        if header_bytes > limits.max_header_bytes {
            return Err(MediaCodecError::HeadersTooLarge {
                part: part_index,
                limit: limits.max_header_bytes,
            });
        }
        let disposition = encode_content_disposition(&part.field_name, filename);

        append_bounded(&mut body, b"--", limits)?;
        append_bounded(&mut body, boundary.as_bytes(), limits)?;
        append_bounded(&mut body, b"\r\nContent-Disposition: ", limits)?;
        append_bounded(&mut body, disposition.as_bytes(), limits)?;
        if let Some(media_type) = media_type {
            append_bounded(&mut body, b"\r\nContent-Type: ", limits)?;
            append_bounded(&mut body, media_type.trim().as_bytes(), limits)?;
        }
        append_bounded(&mut body, b"\r\n\r\n", limits)?;
        append_bounded(&mut body, part_body, limits)?;
        append_bounded(&mut body, b"\r\n", limits)?;
    }
    append_bounded(&mut body, b"--", limits)?;
    append_bounded(&mut body, boundary.as_bytes(), limits)?;
    append_bounded(&mut body, b"--\r\n", limits)?;

    Ok(EncodedMultipartMedia { body, content_type })
}

fn media_fields(part: &ContentPart) -> Result<(&str, &MediaSource, Option<&str>), MediaCodecError> {
    match part {
        ContentPart::Image {
            media_type,
            source,
            detail,
        } if detail.is_none() => Ok((media_type, source, None)),
        ContentPart::Audio { media_type, source } => Ok((media_type, source, None)),
        ContentPart::File {
            name,
            media_type,
            source,
        } => Ok((media_type, source, name.as_deref())),
        ContentPart::Text { .. }
        | ContentPart::Image { .. }
        | ContentPart::Reasoning(_)
        | ContentPart::ToolCall(_)
        | ContentPart::ToolResult(_)
        | ContentPart::Provider { .. } => Err(MediaCodecError::UnsupportedContent),
    }
}

fn inline_bytes(source: &MediaSource) -> Result<&[u8], MediaCodecError> {
    match source {
        MediaSource::Inline(bytes) => Ok(bytes),
        MediaSource::Uri(_) => Err(MediaCodecError::NonInlineSource),
    }
}

fn validate_media_kind(
    part: &ContentPart,
    essence: &str,
    filename: Option<&str>,
) -> Result<(), MediaCodecError> {
    let matches = match part {
        ContentPart::Image { .. } => essence.starts_with("image/") && filename.is_none(),
        ContentPart::Audio { .. } => essence.starts_with("audio/") && filename.is_none(),
        ContentPart::File { .. } => {
            filename.is_some() || (!essence.starts_with("image/") && !essence.starts_with("audio/"))
        }
        ContentPart::Text { .. }
        | ContentPart::Reasoning(_)
        | ContentPart::ToolCall(_)
        | ContentPart::ToolResult(_)
        | ContentPart::Provider { .. } => false,
    };
    if matches {
        Ok(())
    } else {
        Err(MediaCodecError::MediaTypeMismatch)
    }
}

fn part_from_bytes(
    media_type: String,
    essence: String,
    filename: Option<String>,
    body: Vec<u8>,
) -> ContentPart {
    if filename.is_some() {
        ContentPart::file(filename, media_type, MediaSource::inline(body))
    } else if essence.starts_with("image/") {
        ContentPart::image(media_type, MediaSource::inline(body))
    } else if essence.starts_with("audio/") {
        ContentPart::audio(media_type, MediaSource::inline(body))
    } else {
        ContentPart::file(filename, media_type, MediaSource::inline(body))
    }
}

fn decode_text_part(body: &[u8], part: usize) -> Result<ContentPart, MediaCodecError> {
    let text = std::str::from_utf8(body).map_err(|_| MediaCodecError::InvalidText { part })?;
    Ok(ContentPart::text(text))
}

fn contains_boundary_line(body: &[u8], marker: &[u8]) -> bool {
    let mut search = 0;
    while let Some(relative) = find_bytes(&body[search..], marker) {
        let after_marker = search + relative + marker.len();
        let suffix = body.get(after_marker..after_marker.saturating_add(2));
        if after_marker == body.len() || suffix == Some(b"--") || suffix == Some(b"\r\n") {
            return true;
        }
        search = search.saturating_add(relative).saturating_add(1);
    }
    false
}

fn enforce_body_limit(length: usize, limits: MediaLimits) -> Result<(), MediaCodecError> {
    if length > limits.max_body_bytes {
        return Err(MediaCodecError::BodyTooLarge {
            limit: limits.max_body_bytes,
            observed: length,
        });
    }
    Ok(())
}

fn enforce_header_value_limit(value: &str, limits: MediaLimits) -> Result<(), MediaCodecError> {
    if value.len() > limits.max_header_bytes {
        return Err(MediaCodecError::HeaderValueTooLarge {
            limit: limits.max_header_bytes,
            observed: value.len(),
        });
    }
    Ok(())
}

fn append_bounded(
    output: &mut Vec<u8>,
    bytes: &[u8],
    limits: MediaLimits,
) -> Result<(), MediaCodecError> {
    let observed = output.len().saturating_add(bytes.len());
    if observed > limits.max_body_bytes {
        return Err(MediaCodecError::BodyTooLarge {
            limit: limits.max_body_bytes,
            observed,
        });
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn validate_media_type(value: &str) -> Result<String, MediaCodecError> {
    let segments = split_parameters(value).map_err(|_| MediaCodecError::InvalidContentType)?;
    let essence = segments
        .first()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or(MediaCodecError::InvalidContentType)?;
    let (kind, subtype) = essence
        .split_once('/')
        .ok_or(MediaCodecError::InvalidContentType)?;
    if subtype.contains('/') || !is_token(kind) || !is_token(subtype) {
        return Err(MediaCodecError::InvalidContentType);
    }

    let mut parameters = BTreeSet::new();
    for segment in segments.iter().skip(1) {
        let (name, raw_value) = segment
            .split_once('=')
            .ok_or(MediaCodecError::InvalidContentType)?;
        let name = name.trim().to_ascii_lowercase();
        if !is_token(&name)
            || !parameters.insert(name)
            || decode_parameter_value(raw_value).is_err()
        {
            return Err(MediaCodecError::InvalidContentType);
        }
    }
    Ok(format!(
        "{}/{}",
        kind.to_ascii_lowercase(),
        subtype.to_ascii_lowercase()
    ))
}

fn multipart_boundary(content_type: &str) -> Result<String, MediaCodecError> {
    let segments =
        split_parameters(content_type).map_err(|_| MediaCodecError::InvalidContentType)?;
    let media_type = segments
        .first()
        .map(|value| value.trim())
        .ok_or(MediaCodecError::InvalidContentType)?;
    if !media_type.eq_ignore_ascii_case("multipart/form-data") {
        return Err(MediaCodecError::InvalidContentType);
    }

    let mut boundary = None;
    let mut parameters = BTreeSet::new();
    for segment in segments.iter().skip(1) {
        let (name, raw_value) = segment
            .split_once('=')
            .ok_or(MediaCodecError::InvalidContentType)?;
        let name = name.trim().to_ascii_lowercase();
        if !is_token(&name) || !parameters.insert(name.clone()) {
            return Err(MediaCodecError::InvalidContentType);
        }
        if name != "boundary" {
            return Err(MediaCodecError::InvalidContentType);
        }
        let value =
            decode_parameter_value(raw_value).map_err(|_| MediaCodecError::InvalidContentType)?;
        boundary = Some(value);
    }
    let boundary = boundary.ok_or(MediaCodecError::InvalidBoundary)?;
    validate_boundary(&boundary)?;
    Ok(boundary)
}

fn validate_boundary(boundary: &str) -> Result<(), MediaCodecError> {
    if boundary.is_empty() || boundary.len() > 70 || !boundary.bytes().all(is_boundary_character) {
        return Err(MediaCodecError::InvalidBoundary);
    }
    Ok(())
}

fn is_boundary_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn split_parameters(value: &str) -> Result<Vec<&str>, ()> {
    if value.is_empty() || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(());
    }
    let bytes = value.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b';' && !quoted {
            segments.push(&value[start..index]);
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(());
    }
    segments.push(&value[start..]);
    Ok(segments)
}

fn decode_parameter_value(value: &str) -> Result<String, ()> {
    let value = value.trim();
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        let mut output = String::with_capacity(inner.len());
        let mut escaped = false;
        for character in inner.chars() {
            if escaped {
                output.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' || character.is_control() {
                return Err(());
            } else {
                output.push(character);
            }
        }
        if escaped {
            return Err(());
        }
        return Ok(output);
    }
    if is_token(value) {
        Ok(value.to_owned())
    } else {
        Err(())
    }
}

fn find_header_end(
    input: &[u8],
    part: usize,
    limits: MediaLimits,
) -> Result<usize, MediaCodecError> {
    let scan_length = input.len().min(limits.max_header_bytes.saturating_add(4));
    if let Some(index) = find_bytes(&input[..scan_length], b"\r\n\r\n") {
        if index > limits.max_header_bytes {
            return Err(MediaCodecError::HeadersTooLarge {
                part,
                limit: limits.max_header_bytes,
            });
        }
        return Ok(index);
    }
    if input.len() > limits.max_header_bytes {
        return Err(MediaCodecError::HeadersTooLarge {
            part,
            limit: limits.max_header_bytes,
        });
    }
    Err(MediaCodecError::MalformedMultipart)
}

fn parse_part_headers(
    input: &[u8],
    part: usize,
    limits: MediaLimits,
) -> Result<BTreeMap<String, String>, MediaCodecError> {
    let input = std::str::from_utf8(input).map_err(|_| MediaCodecError::MalformedMultipart)?;
    let mut headers = BTreeMap::new();
    if input.is_empty() {
        return Ok(headers);
    }
    for (index, line) in input.split("\r\n").enumerate() {
        if index >= limits.max_headers_per_part {
            return Err(MediaCodecError::TooManyHeaders {
                part,
                limit: limits.max_headers_per_part,
            });
        }
        let (raw_name, raw_value) = line
            .split_once(':')
            .ok_or(MediaCodecError::MalformedMultipart)?;
        if raw_name.trim() != raw_name || !is_token(raw_name) {
            return Err(MediaCodecError::MalformedMultipart);
        }
        let name = raw_name.to_ascii_lowercase();
        let value = raw_value.trim_matches([' ', '\t']);
        if value.is_empty() || value.chars().any(|character| character.is_control()) {
            return Err(MediaCodecError::MalformedMultipart);
        }
        if name != "content-disposition" && name != "content-type" {
            return Err(MediaCodecError::UnsupportedHeader { part, header: name });
        }
        if headers.insert(name.clone(), value.to_owned()).is_some() {
            return Err(MediaCodecError::DuplicateHeader { part, header: name });
        }
    }
    Ok(headers)
}

fn parse_content_disposition(
    headers: &BTreeMap<String, String>,
    part: usize,
) -> Result<(String, Option<String>), MediaCodecError> {
    let value = headers
        .get("content-disposition")
        .ok_or(MediaCodecError::MissingHeader {
            part,
            header: "content-disposition",
        })?;
    let segments = split_parameters(value).map_err(|_| MediaCodecError::MalformedMultipart)?;
    if !segments
        .first()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("form-data"))
    {
        return Err(MediaCodecError::MalformedMultipart);
    }

    let mut parameters = BTreeMap::new();
    for segment in segments.iter().skip(1) {
        let (raw_name, raw_value) = segment
            .split_once('=')
            .ok_or(MediaCodecError::MalformedMultipart)?;
        let name = raw_name.trim().to_ascii_lowercase();
        if !is_token(&name) {
            return Err(MediaCodecError::MalformedMultipart);
        }
        if name != "name" && name != "filename" {
            return Err(MediaCodecError::UnsupportedDispositionParameter {
                part,
                parameter: name,
            });
        }
        let value = decode_parameter_value(raw_value).map_err(|_| {
            MediaCodecError::InvalidDispositionValue {
                part,
                field: if name == "name" { "name" } else { "filename" },
            }
        })?;
        if parameters.insert(name.clone(), value).is_some() {
            return Err(MediaCodecError::DuplicateDispositionParameter {
                part,
                parameter: name,
            });
        }
    }
    let field_name = parameters
        .remove("name")
        .ok_or(MediaCodecError::InvalidDispositionValue {
            part,
            field: "name",
        })?;
    validate_disposition_value(&field_name, part, "name")?;
    let filename = parameters.remove("filename");
    if let Some(filename) = filename.as_deref() {
        validate_disposition_value(filename, part, "filename")?;
    }
    Ok((field_name, filename))
}

fn validate_disposition_value(
    value: &str,
    part: usize,
    field: &'static str,
) -> Result<(), MediaCodecError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(MediaCodecError::InvalidDispositionValue { part, field });
    }
    Ok(())
}

fn encode_content_disposition(field_name: &str, filename: Option<&str>) -> String {
    let mut value = format!("form-data; name=\"{}\"", escape_quoted(field_name));
    if let Some(filename) = filename {
        value.push_str("; filename=\"");
        value.push_str(&escape_quoted(filename));
        value.push('"');
    }
    value
}

fn disposition_value_length(field_name: &str, filename: Option<&str>) -> usize {
    let mut length = "form-data; name=\"\""
        .len()
        .saturating_add(escaped_quoted_length(field_name));
    if let Some(filename) = filename {
        length = length
            .saturating_add("; filename=\"\"".len())
            .saturating_add(escaped_quoted_length(filename));
    }
    length
}

fn escaped_quoted_length(value: &str) -> usize {
    value
        .chars()
        .map(|character| character.len_utf8() + usize::from(matches!(character, '\\' | '"')))
        .fold(0, usize::saturating_add)
}

fn escape_quoted(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '"') {
            output.push('\\');
        }
        output.push(character);
    }
    output
}

fn find_next_boundary(
    input: &[u8],
    start: usize,
    marker: &[u8],
) -> Result<(usize, usize), MediaCodecError> {
    let mut search = start;
    while let Some(relative) = find_bytes(&input[search..], marker) {
        let body_end = search + relative;
        let after_marker = body_end + marker.len();
        let suffix = input.get(after_marker..after_marker.saturating_add(2));
        if suffix == Some(b"--") || suffix == Some(b"\r\n") {
            return Ok((body_end, after_marker));
        }
        search = body_end.saturating_add(1);
    }
    Err(MediaCodecError::MalformedMultipart)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn require_terminal_suffix(input: &[u8]) -> Result<(), MediaCodecError> {
    if input.is_empty() || input == b"\r\n" {
        Ok(())
    } else {
        Err(MediaCodecError::MalformedMultipart)
    }
}
