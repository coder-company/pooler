//! Bounded, metadata-only historical usage records.

use serde::{Deserialize, Serialize};

use crate::{StoreError, StoreResult, Timestamp};

/// Provenance for a persisted cost observation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CostProvenance {
    /// The upstream explicitly returned the stored cost ticks.
    ProviderReported,
    /// Pooler applied an operator-owned, versioned price book.
    OperatorEstimated,
    /// No trustworthy cost was available.
    #[default]
    Unknown,
}

/// One completed request's bounded usage dimensions and measurements.
///
/// Raw request/response content, credentials, authorization data, and secret
/// references have no representation in this type.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsageRecord {
    /// Store-assigned monotonic identifier; zero means not yet persisted.
    pub id: u64,
    pub recorded_at: Timestamp,
    pub request_id: String,
    pub route: String,
    pub provider: Option<String>,
    pub public_model: Option<String>,
    pub upstream_model: Option<String>,
    pub account_pseudonym: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub cache_tokens: Option<u64>,
    pub image_units: Option<u64>,
    pub audio_units: Option<u64>,
    pub video_units: Option<u64>,
    pub latency_ms: u64,
    pub ttft_ms: Option<u64>,
    pub service_tier: Option<String>,
    pub result_class: String,
    pub cost_in_usd_ticks: Option<u64>,
    pub cost_provenance: CostProvenance,
    pub price_book_version: Option<String>,
    pub configuration_generation: u64,
    pub catalog_generation: Option<u64>,
}

impl UsageRecord {
    #[must_use]
    pub fn new(
        recorded_at: Timestamp,
        request_id: impl Into<String>,
        route: impl Into<String>,
        result_class: impl Into<String>,
    ) -> Self {
        Self {
            recorded_at,
            request_id: request_id.into(),
            route: route.into(),
            result_class: result_class.into(),
            ..Self::default()
        }
    }

    pub(crate) fn validate(&self) -> StoreResult<()> {
        for (field, value) in [
            ("request_id", self.request_id.as_str()),
            ("route", self.route.as_str()),
            ("result_class", self.result_class.as_str()),
        ] {
            if value.is_empty() {
                return Err(StoreError::EmptyField { field });
            }
        }
        if self.request_id.len() > 128 || self.route.len() > 128 || self.result_class.len() > 64 {
            return Err(StoreError::Serialization(
                "usage record exceeds metadata bounds".to_owned(),
            ));
        }
        for value in [
            self.provider.as_deref(),
            self.public_model.as_deref(),
            self.upstream_model.as_deref(),
            self.account_pseudonym.as_deref(),
            self.service_tier.as_deref(),
            self.price_book_version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.is_empty() || value.len() > 256 {
                return Err(StoreError::Serialization(
                    "usage dimension exceeds metadata bounds".to_owned(),
                ));
            }
        }
        match self.cost_provenance {
            CostProvenance::ProviderReported
                if self.cost_in_usd_ticks.is_none() || self.price_book_version.is_some() =>
            {
                Err(StoreError::Serialization(
                    "provider-reported cost requires ticks and cannot name a price book".to_owned(),
                ))
            }
            CostProvenance::OperatorEstimated
                if self.cost_in_usd_ticks.is_none() || self.price_book_version.is_none() =>
            {
                Err(StoreError::Serialization(
                    "operator-estimated cost requires ticks and a price-book version".to_owned(),
                ))
            }
            CostProvenance::Unknown
                if self.cost_in_usd_ticks.is_some() || self.price_book_version.is_some() =>
            {
                Err(StoreError::Serialization(
                    "unknown cost cannot carry ticks or a price-book version".to_owned(),
                ))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_estimates_require_versioned_price_book_evidence() {
        let mut record = UsageRecord::new(1, "request", "route", "success");
        record.cost_in_usd_ticks = Some(42);
        record.cost_provenance = CostProvenance::OperatorEstimated;
        assert!(record.validate().is_err());
        record.price_book_version = Some("operator-book@2026-08-22".to_owned());
        assert!(record.validate().is_ok());
    }

    #[test]
    fn unknown_and_provider_cost_invariants_are_strict() {
        let mut record = UsageRecord::new(1, "request", "route", "success");
        record.cost_in_usd_ticks = Some(42);
        assert!(record.validate().is_err());
        record.cost_provenance = CostProvenance::ProviderReported;
        assert!(record.validate().is_ok());
        record.price_book_version = Some("must-not-apply".to_owned());
        assert!(record.validate().is_err());
    }

    #[test]
    fn dimensions_are_bounded() {
        let mut record = UsageRecord::new(1, "request", "route", "success");
        record.provider = Some("x".repeat(257));
        assert!(record.validate().is_err());
    }
}
