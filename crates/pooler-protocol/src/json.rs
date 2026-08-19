//! JSON helpers that retain the original representation until a mutation is
//! requested.

use std::{borrow::Cow, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

/// Default maximum size of a JSON pointer accepted by a patch.
pub const DEFAULT_JSON_PATCH_MAX_POINTER_BYTES: usize = 1024;
/// Default maximum number of path components accepted by a patch.
pub const DEFAULT_JSON_PATCH_MAX_POINTER_DEPTH: usize = 32;
/// Default maximum serialized size of a replacement value.
pub const DEFAULT_JSON_PATCH_MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Errors produced by [`PreservedJson`].
#[derive(Debug, Error)]
pub enum PreservedJsonError {
    /// The input was not a complete JSON document.
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// A JSON pointer did not identify an existing value.
    #[error("JSON pointer `{pointer}` was not found")]
    PointerNotFound {
        /// Pointer that failed to resolve.
        pointer: String,
    },
    /// A JSON pointer selected a value of the wrong kind for the requested
    /// operation.
    #[error("JSON pointer `{pointer}` does not select an object or array")]
    NotContainer {
        /// Pointer that selected a scalar value.
        pointer: String,
    },
    /// Removing the root value would leave no JSON document.
    #[error("the root JSON value cannot be removed")]
    CannotRemoveRoot,
}

/// Errors returned while inspecting an OpenAI-style request.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JsonInspectionError {
    /// The JSON document is not an object and therefore has no top-level
    /// request fields.
    #[error("OpenAI request JSON must be an object")]
    NotObject,
    /// The top-level `model` field exists but is not a string.
    #[error("OpenAI request field `model` must be a string")]
    ModelNotString,
    /// The top-level `model` field is present but empty.
    #[error("OpenAI request field `model` must not be empty")]
    EmptyModel,
    /// A caller required a model but the request did not include one.
    #[error("OpenAI request field `model` is missing")]
    ModelMissing,
}

/// Bounds applied to one JSON pointer patch.
///
/// The limits cover the untrusted pointer text, its path depth, and the
/// serialized replacement value.  They deliberately do not impose a second
/// body-size limit: the route owns the body limit and this type owns only the
/// work introduced by the patch operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonPatchLimits {
    /// Maximum pointer length in UTF-8 bytes.
    pub max_pointer_bytes: usize,
    /// Maximum number of pointer components.
    pub max_pointer_depth: usize,
    /// Maximum compact JSON size of the replacement value in bytes.
    pub max_value_bytes: usize,
}

impl Default for JsonPatchLimits {
    fn default() -> Self {
        Self {
            max_pointer_bytes: DEFAULT_JSON_PATCH_MAX_POINTER_BYTES,
            max_pointer_depth: DEFAULT_JSON_PATCH_MAX_POINTER_DEPTH,
            max_value_bytes: DEFAULT_JSON_PATCH_MAX_VALUE_BYTES,
        }
    }
}

impl JsonPatchLimits {
    /// Creates explicit pointer and replacement-value bounds.
    #[must_use]
    pub const fn new(
        max_pointer_bytes: usize,
        max_pointer_depth: usize,
        max_value_bytes: usize,
    ) -> Self {
        Self {
            max_pointer_bytes,
            max_pointer_depth,
            max_value_bytes,
        }
    }
}

impl JsonPatchError {
    fn invalid_pointer(pointer: &str) -> Self {
        Self::InvalidPointer {
            pointer: pointer.to_owned(),
        }
    }
}

/// Errors returned when a JSON pointer patch cannot be applied.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum JsonPatchError {
    /// The pointer is not an RFC 6901 pointer or contains an invalid escape.
    #[error("invalid JSON pointer `{pointer}`")]
    InvalidPointer {
        /// Pointer supplied by the route.
        pointer: String,
    },
    /// The pointer exceeds the configured byte bound.
    #[error("JSON pointer is too long: {observed} bytes exceeds limit {limit}")]
    PointerTooLong {
        /// Observed pointer length in bytes.
        observed: usize,
        /// Configured pointer-byte limit.
        limit: usize,
    },
    /// The pointer has more components than the configured bound.
    #[error("JSON pointer is too deep: {observed} components exceeds limit {limit}")]
    PointerTooDeep {
        /// Observed pointer depth.
        observed: usize,
        /// Configured pointer-depth limit.
        limit: usize,
    },
    /// The replacement value exceeds the configured serialized-size bound.
    #[error("replacement JSON value is too large: {observed} bytes exceeds limit {limit}")]
    ValueTooLarge {
        /// Compact serialized replacement size in bytes.
        observed: usize,
        /// Configured replacement-size limit.
        limit: usize,
    },
    /// The pointer's parent does not exist.
    #[error("JSON pointer parent for `{pointer}` was not found")]
    PointerNotFound {
        /// Pointer supplied by the route.
        pointer: String,
    },
    /// The pointer's parent is a scalar and cannot contain the target.
    #[error("JSON pointer parent for `{pointer}` is not an object or array")]
    NotContainer {
        /// Pointer supplied by the route.
        pointer: String,
    },
    /// The pointer does not identify an existing array element.
    #[error("JSON pointer `{pointer}` does not identify an array element")]
    ArrayIndexNotFound {
        /// Pointer supplied by the route.
        pointer: String,
    },
    /// The request could not be inspected before patching.
    #[error("cannot inspect request before patching: {0}")]
    Inspection(#[from] JsonInspectionError),
    /// A replacement value could not be serialized for size accounting.
    #[error("cannot serialize replacement JSON value: {message}")]
    ValueSerialization {
        /// Redacted serialization failure text.
        message: String,
    },
}

/// A JSON document that keeps its input bytes until the value is changed.
///
/// This type is useful on inspect and patch routes.  A decode/encode cycle can
/// therefore forward whitespace, object key order, and other harmless details
/// exactly as received.  Once a mutation is made, serialization is delegated
/// to `serde_json` and the original representation is no longer returned.
#[derive(Clone)]
pub struct PreservedJson {
    original: Vec<u8>,
    value: Value,
    modified: bool,
}

impl PreservedJson {
    /// Parses a complete JSON document and retains the supplied bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, PreservedJsonError> {
        let original = bytes.into();
        let value = serde_json::from_slice(&original)?;
        Ok(Self {
            original,
            value,
            modified: false,
        })
    }

    /// Parses a UTF-8 JSON document and retains the supplied bytes.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Result<Self, PreservedJsonError> {
        Self::from_bytes(value.as_bytes().to_vec())
    }

    /// Creates a document from a decoded value.
    ///
    /// The generated bytes are considered the initial representation and will
    /// be returned unchanged until the value is mutated.
    pub fn from_value(value: Value) -> Result<Self, PreservedJsonError> {
        let original = serde_json::to_vec(&value)?;
        Ok(Self {
            original,
            value,
            modified: false,
        })
    }

    /// Returns the decoded value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    /// Returns the original input bytes, regardless of later mutations.
    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Returns whether a mutation has invalidated the original byte form.
    #[must_use]
    pub const fn is_modified(&self) -> bool {
        self.modified
    }

    /// Returns the current representation without needlessly re-serializing an
    /// unmodified document.
    #[must_use]
    pub fn bytes(&self) -> Cow<'_, [u8]> {
        if self.modified {
            Cow::Owned(serde_json::to_vec(&self.value).expect("serde_json::Value is serializable"))
        } else {
            Cow::Borrowed(&self.original)
        }
    }

    /// Returns the current representation as owned bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes().into_owned()
    }

    /// Returns a value selected by an RFC 6901 JSON pointer.
    #[must_use]
    pub fn pointer(&self, pointer: &str) -> Option<&Value> {
        self.value.pointer(pointer)
    }

    /// Extracts the optional top-level `model` field without changing the
    /// retained representation.
    ///
    /// A missing field is valid for inspection because some request layouts
    /// resolve a model from a header or route.  Call [`Self::require_model`]
    /// when the caller needs the field to be present.
    pub fn extract_model(&self) -> Result<Option<&str>, JsonInspectionError> {
        extract_model_from_value(&self.value)
    }

    /// Extracts a required top-level `model` field.
    pub fn require_model(&self) -> Result<&str, JsonInspectionError> {
        self.extract_model()?
            .ok_or(JsonInspectionError::ModelMissing)
    }

    /// Sets a JSON-pointer target under explicit pointer and value bounds.
    ///
    /// Object members may be created by this operation.  Array members must
    /// already exist; this keeps the operation a field transform rather than
    /// an unbounded append primitive.  The returned value is the previous
    /// value, or `None` when an object member was newly created.
    pub fn set_pointer_bounded(
        &mut self,
        pointer: &str,
        value: Value,
        limits: JsonPatchLimits,
    ) -> Result<Option<Value>, JsonPatchError> {
        let tokens = validate_patch(pointer, &value, limits)?;
        self.set_pointer_tokens(pointer, &tokens, value)
    }

    /// Sets a pointer only when the request model starts with `prefix`.
    ///
    /// A missing or non-matching model is a successful no-op and returns
    /// `false`.  Malformed request JSON shape and invalid patch bounds remain
    /// explicit errors.  The operation returns `true` only when the pointer
    /// was applied.
    pub fn set_pointer_when_model_prefix(
        &mut self,
        prefix: &str,
        pointer: &str,
        value: Value,
        limits: JsonPatchLimits,
    ) -> Result<bool, JsonPatchError> {
        let tokens = validate_patch(pointer, &value, limits)?;
        let Some(model) = self.extract_model()? else {
            return Ok(false);
        };
        if !model.starts_with(prefix) {
            return Ok(false);
        }
        self.set_pointer_tokens(pointer, &tokens, value)?;
        Ok(true)
    }

    fn set_pointer_tokens(
        &mut self,
        pointer: &str,
        tokens: &[String],
        value: Value,
    ) -> Result<Option<Value>, JsonPatchError> {
        let Some((last, parent_tokens)) = tokens.split_last() else {
            self.modified = true;
            return Ok(Some(std::mem::replace(&mut self.value, value)));
        };

        let parent = pointer_parent_mut(&mut self.value, parent_tokens, pointer)?;
        let previous = match parent {
            Value::Object(object) => object.insert(last.clone(), value),
            Value::Array(array) => {
                let Some(index) = parse_array_index(last) else {
                    return Err(JsonPatchError::ArrayIndexNotFound {
                        pointer: pointer.to_owned(),
                    });
                };
                let Some(slot) = array.get_mut(index) else {
                    return Err(JsonPatchError::ArrayIndexNotFound {
                        pointer: pointer.to_owned(),
                    });
                };
                Some(std::mem::replace(slot, value))
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                return Err(JsonPatchError::NotContainer {
                    pointer: pointer.to_owned(),
                });
            }
        };
        self.modified = true;
        Ok(previous)
    }

    /// Replaces an existing value selected by a JSON pointer.
    ///
    /// The empty pointer replaces the root.  For non-root pointers this method
    /// intentionally requires the target to exist; callers that need to create
    /// a new object member can use [`Self::insert`].
    pub fn set_pointer(
        &mut self,
        pointer: &str,
        value: Value,
    ) -> Result<Value, PreservedJsonError> {
        if pointer.is_empty() {
            self.modified = true;
            return Ok(std::mem::replace(&mut self.value, value));
        }
        let Some(target) = self.value.pointer_mut(pointer) else {
            return Err(PreservedJsonError::PointerNotFound {
                pointer: pointer.to_owned(),
            });
        };
        self.modified = true;
        Ok(std::mem::replace(target, value))
    }

    /// Alias for [`Self::set_pointer`] used by patch implementations.
    pub fn replace(&mut self, pointer: &str, value: Value) -> Result<Value, PreservedJsonError> {
        self.set_pointer(pointer, value)
    }

    /// Inserts or replaces an object member at a JSON pointer.
    ///
    /// The pointer must identify an existing object.  An empty pointer is not a
    /// valid parent for this operation.
    pub fn insert(
        &mut self,
        object_pointer: &str,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Option<Value>, PreservedJsonError> {
        let key = key.into();
        let Some(parent) = self.value.pointer_mut(object_pointer) else {
            return Err(PreservedJsonError::PointerNotFound {
                pointer: object_pointer.to_owned(),
            });
        };
        let Value::Object(object) = parent else {
            return Err(PreservedJsonError::NotContainer {
                pointer: object_pointer.to_owned(),
            });
        };
        self.modified = true;
        Ok(object.insert(key, value))
    }

    /// Removes an existing value selected by a JSON pointer.
    pub fn remove(&mut self, pointer: &str) -> Result<Value, PreservedJsonError> {
        if pointer.is_empty() {
            return Err(PreservedJsonError::CannotRemoveRoot);
        }
        let Some((parent_pointer, token)) = split_pointer(pointer) else {
            return Err(PreservedJsonError::PointerNotFound {
                pointer: pointer.to_owned(),
            });
        };
        let Some(parent) = self.value.pointer_mut(parent_pointer) else {
            return Err(PreservedJsonError::PointerNotFound {
                pointer: parent_pointer.to_owned(),
            });
        };
        let Some(token) = decode_pointer_token(token) else {
            return Err(PreservedJsonError::PointerNotFound {
                pointer: pointer.to_owned(),
            });
        };
        let removed = match parent {
            Value::Object(object) => object.remove(&token),
            Value::Array(array) => token
                .parse::<usize>()
                .ok()
                .and_then(|index| (index < array.len()).then(|| array.remove(index))),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
        };
        let Some(removed) = removed else {
            return Err(PreservedJsonError::PointerNotFound {
                pointer: pointer.to_owned(),
            });
        };
        self.modified = true;
        Ok(removed)
    }

    /// Applies a bounded mutation and marks the representation as modified.
    pub fn edit<F>(&mut self, edit: F)
    where
        F: FnOnce(&mut Value),
    {
        edit(&mut self.value);
        self.modified = true;
    }
}

fn extract_model_from_value(value: &Value) -> Result<Option<&str>, JsonInspectionError> {
    let Value::Object(object) = value else {
        return Err(JsonInspectionError::NotObject);
    };
    let Some(model) = object.get("model") else {
        return Ok(None);
    };
    let Some(model) = model.as_str() else {
        return Err(JsonInspectionError::ModelNotString);
    };
    if model.trim().is_empty() {
        return Err(JsonInspectionError::EmptyModel);
    }
    Ok(Some(model))
}

fn validate_patch(
    pointer: &str,
    value: &Value,
    limits: JsonPatchLimits,
) -> Result<Vec<String>, JsonPatchError> {
    if pointer.len() > limits.max_pointer_bytes {
        return Err(JsonPatchError::PointerTooLong {
            observed: pointer.len(),
            limit: limits.max_pointer_bytes,
        });
    }

    let tokens = parse_pointer(pointer)?;
    if tokens.len() > limits.max_pointer_depth {
        return Err(JsonPatchError::PointerTooDeep {
            observed: tokens.len(),
            limit: limits.max_pointer_depth,
        });
    }

    let observed = serde_json::to_vec(value)
        .map_err(|error| JsonPatchError::ValueSerialization {
            message: error.to_string(),
        })?
        .len();
    if observed > limits.max_value_bytes {
        return Err(JsonPatchError::ValueTooLarge {
            observed,
            limit: limits.max_value_bytes,
        });
    }
    Ok(tokens)
}

fn parse_pointer(pointer: &str) -> Result<Vec<String>, JsonPatchError> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    if !pointer.starts_with('/') {
        return Err(JsonPatchError::invalid_pointer(pointer));
    }
    pointer[1..]
        .split('/')
        .map(|token| {
            decode_pointer_token(token).ok_or_else(|| JsonPatchError::invalid_pointer(pointer))
        })
        .collect()
}

fn pointer_parent_mut<'a>(
    value: &'a mut Value,
    tokens: &[String],
    pointer: &str,
) -> Result<&'a mut Value, JsonPatchError> {
    let mut current = value;
    for token in tokens {
        current = match current {
            Value::Object(object) => {
                object
                    .get_mut(token)
                    .ok_or_else(|| JsonPatchError::PointerNotFound {
                        pointer: pointer.to_owned(),
                    })?
            }
            Value::Array(array) => {
                let Some(index) = parse_array_index(token) else {
                    return Err(JsonPatchError::ArrayIndexNotFound {
                        pointer: pointer.to_owned(),
                    });
                };
                array
                    .get_mut(index)
                    .ok_or_else(|| JsonPatchError::ArrayIndexNotFound {
                        pointer: pointer.to_owned(),
                    })?
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                return Err(JsonPatchError::NotContainer {
                    pointer: pointer.to_owned(),
                });
            }
        };
    }
    Ok(current)
}

fn parse_array_index(token: &str) -> Option<usize> {
    if token == "0" || !token.starts_with('0') {
        token.parse::<usize>().ok()
    } else {
        None
    }
}

fn split_pointer(pointer: &str) -> Option<(&str, &str)> {
    let separator = pointer.rfind('/')?;
    let (parent, token) = pointer.split_at(separator);
    Some((if parent.is_empty() { "" } else { parent }, &token[1..]))
}

fn decode_pointer_token(token: &str) -> Option<String> {
    let mut decoded = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(character) = chars.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match chars.next()? {
            '0' => decoded.push('~'),
            '1' => decoded.push('/'),
            _ => return None,
        }
    }
    Some(decoded)
}

impl PartialEq for PreservedJson {
    fn eq(&self, other: &Self) -> bool {
        self.original == other.original
            && self.value == other.value
            && self.modified == other.modified
    }
}

impl fmt::Debug for PreservedJson {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreservedJson")
            .field("byte_len", &self.bytes().len())
            .field("modified", &self.modified)
            .finish()
    }
}

impl Serialize for PreservedJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PreservedJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<Vec<u8>> for PreservedJson {
    type Error = PreservedJsonError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl TryFrom<&[u8]> for PreservedJson {
    type Error = PreservedJsonError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value.to_vec())
    }
}

impl TryFrom<&str> for PreservedJson {
    type Error = PreservedJsonError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl FromStr for PreservedJson {
    type Err = PreservedJsonError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(value.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{JsonPatchError, JsonPatchLimits, PreservedJson, PreservedJsonError};

    #[test]
    fn untouched_input_keeps_original_bytes() {
        let input = b"{ \"b\": 2, \"a\": [1, 2] }\n";
        let json = PreservedJson::from_bytes(input.to_vec()).expect("valid JSON");
        assert_eq!(json.bytes().as_ref(), input);
        assert_eq!(json.original_bytes(), input);
        assert!(!json.is_modified());
    }

    #[test]
    fn mutation_switches_to_serialized_value() {
        let mut json = PreservedJson::from_str("{\"value\":1}").expect("valid JSON");
        let previous = json
            .set_pointer("/value", json!(2))
            .expect("existing pointer");
        assert_eq!(previous, json!(1));
        assert_eq!(json.bytes().as_ref(), br#"{"value":2}"#);
        assert!(json.is_modified());
    }

    #[test]
    fn insert_and_remove_escape_pointer_tokens() {
        let mut json = PreservedJson::from_str("{\"a/b\":{}}").expect("valid JSON");
        json.insert("/a~1b", "~key", json!(true)).expect("object");
        assert_eq!(json.pointer("/a~1b/~0key"), Some(&json!(true)));
        let removed = json.remove("/a~1b/~0key").expect("existing value");
        assert_eq!(removed, json!(true));
    }

    #[test]
    fn scalar_insert_reports_container_error() {
        let mut json = PreservedJson::from_str("{\"value\":1}").expect("valid JSON");
        let error = json
            .insert("/value", "nested", json!(2))
            .expect_err("scalar");
        assert!(matches!(error, PreservedJsonError::NotContainer { .. }));
    }

    #[test]
    fn extracts_top_level_model_without_modifying_bytes() {
        let input = br#"{ "model": "gpt-5.6-sol", "unknown": true }"#;
        let json = PreservedJson::from_bytes(input.to_vec()).expect("valid JSON");
        assert_eq!(json.require_model().expect("model"), "gpt-5.6-sol");
        assert_eq!(json.bytes().as_ref(), input);
    }

    #[test]
    fn conditional_patch_preserves_unrelated_structure() {
        let mut json = PreservedJson::from_str(
            r#"{"model":"gpt-5.6-sol","reasoning":{"effort":"low"},"unknown":{"keep":[1,2]}}"#,
        )
        .expect("valid JSON");
        assert!(json
            .set_pointer_when_model_prefix(
                "gpt-5.6-",
                "/reasoning/effort",
                json!("high"),
                JsonPatchLimits::default(),
            )
            .expect("patch"));
        assert_eq!(json.pointer("/reasoning/effort"), Some(&json!("high")));
        assert_eq!(json.pointer("/unknown/keep"), Some(&json!([1, 2])));
    }

    #[test]
    fn model_mismatch_is_a_byte_preserving_noop() {
        let input = br#"{"model":"other","reasoning":{"effort":"low"}}"#;
        let mut json = PreservedJson::from_bytes(input.to_vec()).expect("valid JSON");
        assert!(!json
            .set_pointer_when_model_prefix(
                "gpt-",
                "/reasoning/effort",
                json!("high"),
                JsonPatchLimits::default(),
            )
            .expect("no-op"));
        assert_eq!(json.bytes().as_ref(), input);
    }

    #[test]
    fn bounded_patch_rejects_pointer_and_value_excess() {
        let mut json = PreservedJson::from_str(r#"{"a":1}"#).expect("valid JSON");
        let pointer = json
            .set_pointer_bounded("/a", json!(2), JsonPatchLimits::new(1, 1, 16))
            .expect_err("pointer too long");
        assert!(matches!(pointer, JsonPatchError::PointerTooLong { .. }));

        let value = json
            .set_pointer_bounded("/a", json!("too large"), JsonPatchLimits::new(8, 1, 2))
            .expect_err("value too large");
        assert!(matches!(value, JsonPatchError::ValueTooLarge { .. }));
    }
}
