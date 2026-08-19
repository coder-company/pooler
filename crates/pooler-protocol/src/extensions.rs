//! Provider-specific data that must survive a semantic conversion.
//!
//! Extensions deliberately have a small, boring contract.  They are named by
//! a validated namespace and name, carry bytes together with their media type,
//! and state whether those bytes may be replayed.  In particular, an extension
//! is not a second untyped metadata map: keeping the bytes and replay policy
//! together makes it possible for an encoder to make a safe decision.

use std::fmt;

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Errors returned while creating a namespaced extension.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    /// A namespace or extension name was empty or contained an invalid byte.
    #[error("invalid extension {kind} `{value}`; use ASCII letters, digits, '.', '_' or '-'")]
    InvalidComponent {
        /// The component that failed validation (`namespace` or `name`).
        kind: &'static str,
        /// The rejected value.
        value: String,
    },
    /// A media type is required for an extension payload.
    #[error("extension media type cannot be empty")]
    EmptyMediaType,
    /// An extension key did not contain a namespace and a name.
    #[error("invalid extension key `{0}`; expected `namespace.name`")]
    InvalidKey(String),
}

fn validate_component(value: &str, kind: &'static str) -> Result<(), ExtensionError> {
    let valid = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if valid {
        Ok(())
    } else {
        Err(ExtensionError::InvalidComponent {
            kind,
            value: value.to_owned(),
        })
    }
}

/// A validated extension namespace such as `openai.responses`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtensionNamespace(String);

impl ExtensionNamespace {
    /// Creates a namespace after validating its stable wire representation.
    pub fn new(value: impl Into<String>) -> Result<Self, ExtensionError> {
        let value = value.into();
        validate_component(&value, "namespace")?;
        Ok(Self(value))
    }

    /// Returns the namespace as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ExtensionNamespace {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ExtensionNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for ExtensionNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExtensionNamespace")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for ExtensionNamespace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ExtensionNamespace {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A validated name within an extension namespace.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtensionName(String);

impl ExtensionName {
    /// Creates an extension name after validating its stable wire representation.
    pub fn new(value: impl Into<String>) -> Result<Self, ExtensionError> {
        let value = value.into();
        validate_component(&value, "name")?;
        Ok(Self(value))
    }

    /// Returns the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ExtensionName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ExtensionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for ExtensionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExtensionName")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for ExtensionName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ExtensionName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// The stable, printable identity of an extension.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtensionKey {
    /// The owning namespace.
    pub namespace: ExtensionNamespace,
    /// The extension name within the namespace.
    pub name: ExtensionName,
}

impl ExtensionKey {
    /// Creates a key from a namespace and name.
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, ExtensionError> {
        Ok(Self {
            namespace: ExtensionNamespace::new(namespace)?,
            name: ExtensionName::new(name)?,
        })
    }

    /// Parses a dotted key, splitting at the final dot so dotted namespaces
    /// such as `openai.responses` remain intact.
    pub fn parse(value: impl Into<String>) -> Result<Self, ExtensionError> {
        let value = value.into();
        let Some((namespace, name)) = value.rsplit_once('.') else {
            return Err(ExtensionError::InvalidKey(value));
        };
        Self::new(namespace, name)
    }

    /// Returns the namespace and name joined by a dot.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("{}.{}", self.namespace, self.name)
    }
}

impl fmt::Display for ExtensionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.namespace, self.name)
    }
}

impl fmt::Debug for ExtensionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExtensionKey")
            .field(&self.as_str())
            .finish()
    }
}

impl Serialize for ExtensionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for ExtensionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Controls whether an extension may be sent again on a replayed request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayPolicy {
    /// The extension represents a one-shot side effect and must never be replayed.
    #[default]
    Never,
    /// The extension may be replayed only after the route has established that
    /// the request itself is safe to replay.
    IfSafe,
    /// The extension is explicitly safe to replay.
    Always,
}

impl ReplayPolicy {
    /// Compatibility spelling for callers that use “safe” for `IfSafe`.
    pub const SAFE: Self = Self::IfSafe;

    /// Returns whether this policy permits replay for a route that has already
    /// established replay safety.
    #[must_use]
    pub const fn allows_replay(self, request_is_safe: bool) -> bool {
        match self {
            Self::Never => false,
            Self::IfSafe => request_is_safe,
            Self::Always => true,
        }
    }
}

/// A provider-specific payload that a semantic conversion must not silently
/// discard.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueExtension {
    /// Extension namespace.
    pub namespace: ExtensionNamespace,
    /// Extension name within the namespace.
    pub name: ExtensionName,
    /// Payload media type.
    pub media_type: String,
    /// Whether a replay may carry this extension again.
    pub replay_policy: ReplayPolicy,
    /// Raw extension bytes.
    pub bytes: Vec<u8>,
}

impl OpaqueExtension {
    /// Creates an extension with the default binary media type and a
    /// conservative non-replayable policy.
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, ExtensionError> {
        Ok(Self {
            namespace: ExtensionNamespace::new(namespace)?,
            name: ExtensionName::new(name)?,
            media_type: "application/octet-stream".to_owned(),
            replay_policy: ReplayPolicy::default(),
            bytes: bytes.into(),
        })
    }

    /// Creates an extension from a validated key.
    pub fn from_key(key: ExtensionKey, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            namespace: key.namespace,
            name: key.name,
            media_type: "application/octet-stream".to_owned(),
            replay_policy: ReplayPolicy::default(),
            bytes: bytes.into(),
        }
    }

    /// Sets the media type for this extension.
    pub fn with_media_type(
        mut self,
        media_type: impl Into<String>,
    ) -> Result<Self, ExtensionError> {
        let media_type = media_type.into();
        if media_type.trim().is_empty() {
            return Err(ExtensionError::EmptyMediaType);
        }
        self.media_type = media_type;
        Ok(self)
    }

    /// Sets the replay policy for this extension.
    #[must_use]
    pub const fn with_replay_policy(mut self, replay_policy: ReplayPolicy) -> Self {
        self.replay_policy = replay_policy;
        self
    }

    /// Returns the extension's stable key.
    #[must_use]
    pub fn key(&self) -> ExtensionKey {
        ExtensionKey {
            namespace: self.namespace.clone(),
            name: self.name.clone(),
        }
    }

    /// Returns the payload length without exposing payload bytes in logs.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns the payload bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for OpaqueExtension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueExtension")
            .field("key", &self.key())
            .field("media_type", &self.media_type)
            .field("replay_policy", &self.replay_policy)
            .field("byte_len", &self.byte_len())
            .finish()
    }
}

/// An ordered collection of opaque extensions.
///
/// The order is retained because some providers treat extension records as an
/// ordered stream.  Inserting an existing key replaces its payload while
/// retaining its original position.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Extensions(IndexMap<ExtensionKey, OpaqueExtension>);

/// Alias used by callers that want to emphasize that the entries are opaque.
pub type OpaqueExtensions = Extensions;

impl Extensions {
    /// Creates an empty extension collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an extension, replacing any existing entry with the same key.
    pub fn insert(&mut self, extension: OpaqueExtension) -> Option<OpaqueExtension> {
        self.0.insert(extension.key(), extension)
    }

    /// Removes an extension by key.
    pub fn remove(&mut self, key: &ExtensionKey) -> Option<OpaqueExtension> {
        self.0.shift_remove(key)
    }

    /// Looks up an extension by key.
    #[must_use]
    pub fn get(&self, key: &ExtensionKey) -> Option<&OpaqueExtension> {
        self.0.get(key)
    }

    /// Looks up an extension by dotted key.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&OpaqueExtension> {
        ExtensionKey::parse(key).ok().and_then(|key| self.get(&key))
    }

    /// Returns whether the collection contains a key.
    #[must_use]
    pub fn contains_key(&self, key: &ExtensionKey) -> bool {
        self.0.contains_key(key)
    }

    /// Returns the number of extensions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no extensions are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over extensions in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&ExtensionKey, &OpaqueExtension)> {
        self.0.iter()
    }

    /// Appends all entries from another collection in insertion order.
    pub fn extend(&mut self, other: Self) {
        for extension in other {
            self.insert(extension);
        }
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.0.values()).finish()
    }
}

impl IntoIterator for Extensions {
    type Item = OpaqueExtension;
    type IntoIter = indexmap::map::IntoValues<ExtensionKey, OpaqueExtension>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_values()
    }
}

impl<'a> IntoIterator for &'a Extensions {
    type Item = (&'a ExtensionKey, &'a OpaqueExtension);
    type IntoIter = indexmap::map::Iter<'a, ExtensionKey, OpaqueExtension>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::{ExtensionKey, Extensions, OpaqueExtension, ReplayPolicy};

    #[test]
    fn parses_dotted_namespace_from_the_right() {
        let key = ExtensionKey::parse("openai.responses.encrypted_content").expect("valid key");
        assert_eq!(key.namespace.as_str(), "openai.responses");
        assert_eq!(key.name.as_str(), "encrypted_content");
        assert_eq!(key.as_str(), "openai.responses.encrypted_content");
    }

    #[test]
    fn debug_never_contains_extension_bytes() {
        let extension = OpaqueExtension::new("provider", "secret", b"do-not-log".to_vec())
            .expect("valid extension")
            .with_replay_policy(ReplayPolicy::Always);
        let debug = format!("{extension:?}");
        assert!(debug.contains("byte_len"));
        assert!(debug.contains("10"));
        assert!(!debug.contains("do-not-log"));
    }

    #[test]
    fn replacement_preserves_insertion_order() {
        let first = OpaqueExtension::new("one", "value", vec![1]).expect("valid extension");
        let second = OpaqueExtension::new("two", "value", vec![2]).expect("valid extension");
        let replacement = OpaqueExtension::new("one", "value", vec![3]).expect("valid extension");
        let mut extensions = Extensions::new();
        extensions.insert(first);
        extensions.insert(second);
        extensions.insert(replacement);
        let keys = extensions
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["one.value", "two.value"]);
        assert_eq!(
            extensions.get_str("one.value").expect("entry").as_bytes(),
            &[3]
        );
    }

    #[test]
    fn serialization_is_round_trippable() {
        let extension = OpaqueExtension::new("anthropic.thinking", "signature", vec![1, 2, 3])
            .expect("valid extension")
            .with_media_type("application/octet-stream")
            .expect("valid media type");
        let mut extensions = Extensions::new();
        extensions.insert(extension);
        let encoded = serde_json::to_string(&extensions).expect("serialize");
        let decoded: Extensions = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, extensions);
    }
}
