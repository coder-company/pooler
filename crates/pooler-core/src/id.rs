//! Strongly typed identifiers shared by every Pooler component.

use std::{borrow::Borrow, fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

/// The maximum length accepted for a named identifier.
pub const MAX_IDENTIFIER_LENGTH: usize = 256;

/// Errors returned while constructing a validated identifier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdentifierError {
    /// An identifier was empty or contained only whitespace.
    #[error("identifier must not be empty")]
    Empty,
    /// An identifier was longer than the supported bound.
    #[error("identifier exceeds the {max}-byte limit")]
    TooLong { max: usize },
    /// An identifier contained a control or whitespace character.
    #[error("identifier contains invalid character {character:?}")]
    InvalidCharacter { character: char },
    /// A component identifier did not have a valid namespace segment.
    #[error("component identifier has invalid namespace segment {segment:?}")]
    InvalidComponent { segment: String },
}

fn validate_named(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(IdentifierError::TooLong {
            max: MAX_IDENTIFIER_LENGTH,
        });
    }
    for character in value.chars() {
        if character.is_control() || character.is_whitespace() {
            return Err(IdentifierError::InvalidCharacter { character });
        }
    }
    Ok(())
}

fn validate_component(value: &str) -> Result<(), IdentifierError> {
    validate_named(value)?;
    for segment in value.split('.') {
        if segment.is_empty()
            || !segment.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
        {
            return Err(IdentifierError::InvalidComponent {
                segment: segment.to_owned(),
            });
        }
    }
    Ok(())
}

macro_rules! named_identifier {
    ($name:ident, $validator:ident) => {
        /// A validated, human-readable identifier used in configuration.
        #[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
        #[repr(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct an identifier after validating its syntax and size.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                $validator(&value)?;
                Ok(Self(value))
            }

            /// Return the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume the identifier and return its owned string.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

named_identifier!(RouteId, validate_named);
named_identifier!(ListenerId, validate_named);
named_identifier!(ProviderId, validate_named);
named_identifier!(CredentialId, validate_named);
named_identifier!(ModelId, validate_named);
named_identifier!(SessionId, validate_named);
named_identifier!(TargetId, validate_named);
named_identifier!(ComponentId, validate_component);

/// Composite identity for one public-model target binding.
///
/// A target ID is stable in configuration, while the model component keeps
/// affinity and health state from colliding when a legacy or imported source
/// reuses the same target spelling under a different public model.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct TargetBindingId {
    model: ModelId,
    target: TargetId,
}

impl TargetBindingId {
    /// Construct a composite model/target identity.
    pub fn new(
        model: impl Into<String>,
        target: impl Into<String>,
    ) -> Result<Self, IdentifierError> {
        Ok(Self {
            model: ModelId::new(model)?,
            target: TargetId::new(target)?,
        })
    }

    /// Public model component.
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.model
    }

    /// Stable target component.
    #[must_use]
    pub fn target(&self) -> &TargetId {
        &self.target
    }

    /// Canonical persisted representation.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("{}/{}", self.model, self.target)
    }
}

impl fmt::Debug for TargetBindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TargetBindingId")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for TargetBindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.model, self.target)
    }
}

macro_rules! uuid_identifier {
    ($name:ident) => {
        /// A UUID-backed identifier generated for one runtime request or trace.
        #[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generate a new random identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Construct an identifier from an existing UUID.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Return the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            /// Parse a hyphenated or compact UUID representation.
            pub fn parse(value: &str) -> Result<Self, uuid::Error> {
                Ok(Self(Uuid::parse_str(value)?))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.as_uuid()
            }
        }
    };
}

uuid_identifier!(RequestId);
uuid_identifier!(TraceId);

/// Monotonically increasing generation assigned to a compiled configuration.
///
/// A generation is copied into a request context at admission time. Reloading a
/// configuration creates the next generation; an in-flight request continues to
/// use the generation it already captured.
#[derive(
    Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct ConfigGeneration(u64);

impl ConfigGeneration {
    /// The initial generation used before the first reload.
    pub const INITIAL: Self = Self(0);

    /// Construct a generation from its persisted numeric value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the numeric generation value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Return the generation after one successful reload.
    ///
    /// Saturation avoids wrapping back to an old generation after the counter
    /// reaches its representable maximum.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Whether this is the initial generation.
    #[must_use]
    pub const fn is_initial(self) -> bool {
        self.0 == 0
    }
}

impl From<u64> for ConfigGeneration {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<ConfigGeneration> for u64 {
    fn from(value: ConfigGeneration) -> Self {
        value.value()
    }
}

impl fmt::Display for ConfigGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_ids_validate_and_round_trip() {
        let route = RouteId::new("factory-language-model").expect("valid route ID");
        assert_eq!(route.as_str(), "factory-language-model");
        assert_eq!(route.to_string(), "factory-language-model");
        assert_eq!("factory-language-model".parse::<RouteId>(), Ok(route));
        assert!(RouteId::new("").is_err());
        assert!(RouteId::new("has whitespace").is_err());
        assert!(RouteId::new("has\nnewline").is_err());
    }

    #[test]
    fn component_ids_are_namespaced_and_strict() {
        assert!(ComponentId::new("inspect.openai.model").is_ok());
        assert!(ComponentId::new("custom_transform-v2").is_ok());
        assert!(ComponentId::new("inspect/openai").is_err());
        assert!(ComponentId::new("inspect..model").is_err());
    }

    #[test]
    fn named_id_deserialization_revalidates() {
        let valid: RouteId = serde_json::from_str("\"my-route\"").expect("valid ID");
        assert_eq!(valid.as_str(), "my-route");
        assert!(serde_json::from_str::<RouteId>("\"bad route\"").is_err());
    }

    #[test]
    fn uuid_ids_parse_and_serialize() {
        let uuid = Uuid::from_u128(1);
        let request = RequestId::from_uuid(uuid);
        assert_eq!(request.as_uuid(), uuid);
        assert_eq!(request.to_string(), "00000000-0000-0000-0000-000000000001");
        let parsed: RequestId = request.to_string().parse().expect("valid UUID");
        assert_eq!(parsed, request);
        let json = serde_json::to_string(&request).expect("serialize UUID ID");
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000001\"");
    }

    #[test]
    fn generations_are_monotonic_and_saturating() {
        assert!(ConfigGeneration::INITIAL.is_initial());
        assert_eq!(ConfigGeneration::INITIAL.next().value(), 1);
        assert_eq!(ConfigGeneration::new(u64::MAX).next().value(), u64::MAX);
        assert_eq!(ConfigGeneration::new(4).to_string(), "4");
    }
}
