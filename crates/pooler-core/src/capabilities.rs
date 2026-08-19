//! Capability declarations used by model targets and route plans.

use std::{fmt, iter::FromIterator, ops};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A semantic or transport capability that may be advertised by a target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Capability {
    Text = 0,
    Images,
    Audio,
    Files,
    Tools,
    Reasoning,
    Streaming,
    Usage,
    StructuredOutput,
    JsonSchema,
    FunctionCalling,
    ToolChoice,
    CacheHints,
    Continuation,
    ResponseMetadata,
    EncryptedReasoning,
    Refusal,
    ErrorEvents,
    InputAudio,
    OutputAudio,
    CodeExecution,
    ComputerUse,
    Batch,
    Embeddings,
    Sse,
    WebSocket,
    ConnectRpc,
    Protobuf,
}

impl Capability {
    /// Every capability known by this version of Pooler.
    pub const ALL: [Self; 28] = [
        Self::Text,
        Self::Images,
        Self::Audio,
        Self::Files,
        Self::Tools,
        Self::Reasoning,
        Self::Streaming,
        Self::Usage,
        Self::StructuredOutput,
        Self::JsonSchema,
        Self::FunctionCalling,
        Self::ToolChoice,
        Self::CacheHints,
        Self::Continuation,
        Self::ResponseMetadata,
        Self::EncryptedReasoning,
        Self::Refusal,
        Self::ErrorEvents,
        Self::InputAudio,
        Self::OutputAudio,
        Self::CodeExecution,
        Self::ComputerUse,
        Self::Batch,
        Self::Embeddings,
        Self::Sse,
        Self::WebSocket,
        Self::ConnectRpc,
        Self::Protobuf,
    ];

    const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }

    /// Return the canonical configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Images => "images",
            Self::Audio => "audio",
            Self::Files => "files",
            Self::Tools => "tools",
            Self::Reasoning => "reasoning",
            Self::Streaming => "streaming",
            Self::Usage => "usage",
            Self::StructuredOutput => "structured_output",
            Self::JsonSchema => "json_schema",
            Self::FunctionCalling => "function_calling",
            Self::ToolChoice => "tool_choice",
            Self::CacheHints => "cache_hints",
            Self::Continuation => "continuation",
            Self::ResponseMetadata => "response_metadata",
            Self::EncryptedReasoning => "encrypted_reasoning",
            Self::Refusal => "refusal",
            Self::ErrorEvents => "error_events",
            Self::InputAudio => "input_audio",
            Self::OutputAudio => "output_audio",
            Self::CodeExecution => "code_execution",
            Self::ComputerUse => "computer_use",
            Self::Batch => "batch",
            Self::Embeddings => "embeddings",
            Self::Sse => "sse",
            Self::WebSocket => "web_socket",
            Self::ConnectRpc => "connect_rpc",
            Self::Protobuf => "protobuf",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A compact set of capabilities suitable for immutable route and model plans.
///
/// The representation is a bitset so capability matching is allocation-free on
/// the request path. Unknown bits are never accepted when decoding persisted
/// values; this prevents silently treating a future required capability as one
/// that an older runtime supports.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    const KNOWN_BITS: u64 = (1u64 << Capability::ALL.len()) - 1;

    /// Construct an empty capability set.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Construct a set containing every capability known to this version.
    #[must_use]
    pub const fn all() -> Self {
        Self(Self::KNOWN_BITS)
    }

    /// Construct a set from raw bits, rejecting bits unknown to this version.
    pub const fn try_from_bits(bits: u64) -> Result<Self, u64> {
        if bits & !Self::KNOWN_BITS == 0 {
            Ok(Self(bits))
        } else {
            Err(bits & !Self::KNOWN_BITS)
        }
    }

    /// Return the raw representation for persistence or diagnostics.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether no capabilities are present.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Number of capabilities in this set.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Whether a capability is present.
    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Whether every capability in `required` is present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Whether at least one capability in `candidates` is present.
    #[must_use]
    pub const fn contains_any(self, candidates: Self) -> bool {
        self.0 & candidates.0 != 0
    }

    /// Add one capability and return the resulting set.
    #[must_use]
    pub const fn with(self, capability: Capability) -> Self {
        Self(self.0 | capability.bit())
    }

    /// Add one capability in place.
    pub const fn insert(&mut self, capability: Capability) {
        self.0 |= capability.bit();
    }

    /// Remove one capability in place.
    pub const fn remove(&mut self, capability: Capability) {
        self.0 &= !capability.bit();
    }

    /// Return the union of this set and `other`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return only capabilities present in both sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Return capabilities present in this set but not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Iterate in stable enum declaration order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |capability| self.contains(*capability))
    }
}

impl From<Capability> for CapabilitySet {
    fn from(capability: Capability) -> Self {
        Self::new().with(capability)
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<T: IntoIterator<Item = Capability>>(iter: T) -> Self {
        let mut set = Self::new();
        set.extend(iter);
        set
    }
}

impl Extend<Capability> for CapabilitySet {
    fn extend<T: IntoIterator<Item = Capability>>(&mut self, iter: T) {
        for capability in iter {
            self.insert(capability);
        }
    }
}

impl IntoIterator for CapabilitySet {
    type Item = Capability;
    type IntoIter = std::vec::IntoIter<Capability>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter().collect::<Vec<_>>().into_iter()
    }
}

impl ops::BitOr for CapabilitySet {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl ops::BitOr<Capability> for CapabilitySet {
    type Output = Self;

    fn bitor(self, rhs: Capability) -> Self::Output {
        self.with(rhs)
    }
}

impl ops::BitAnd for CapabilitySet {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.intersection(rhs)
    }
}

impl ops::Sub for CapabilitySet {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.difference(rhs)
    }
}

impl Serialize for CapabilitySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.iter().collect::<Vec<_>>().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<Capability>::deserialize(deserializer)?;
        Ok(values.into_iter().collect())
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut values = self.iter();
        if let Some(first) = values.next() {
            write!(formatter, "{first}")?;
            for capability in values {
                write!(formatter, ", {capability}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_sets_match_without_allocations() {
        let mut set = CapabilitySet::new();
        set.insert(Capability::Text);
        set.insert(Capability::Tools);
        set.insert(Capability::Streaming);
        assert_eq!(set.len(), 3);
        assert!(set.contains_all(CapabilitySet::from_iter([
            Capability::Text,
            Capability::Tools,
        ])));
        assert!(set.contains_any(CapabilitySet::from(Capability::Images) | Capability::Tools));
        set.remove(Capability::Tools);
        assert!(!set.contains(Capability::Tools));
    }

    #[test]
    fn capability_set_operations_and_serialization_are_stable() {
        let left = CapabilitySet::from_iter([Capability::Text, Capability::Tools]);
        let right = CapabilitySet::from_iter([Capability::Tools, Capability::Reasoning]);
        assert_eq!((left | right).len(), 3);
        assert_eq!((left & right).len(), 1);
        assert_eq!((left - right).len(), 1);
        assert_eq!(left.to_string(), "text, tools");
        let json = serde_json::to_string(&left).expect("serialize capabilities");
        assert_eq!(json, "[\"text\",\"tools\"]");
        assert_eq!(serde_json::from_str::<CapabilitySet>(&json).unwrap(), left);
    }

    #[test]
    fn unknown_raw_bits_are_rejected() {
        assert!(CapabilitySet::try_from_bits(1u64 << 63).is_err());
        assert_eq!(CapabilitySet::all().len(), Capability::ALL.len() as u32);
    }
}
