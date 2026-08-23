//! Explicit, versioned operator price books for usage estimates.

use std::sync::Arc;

use serde::Deserialize;

/// Optional operator-owned pricing declaration.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UsagePriceBookConfig {
    /// Stable version included with every estimated cost.
    pub version: String,
    /// Provider/model rates. The first duplicate is rejected during compilation.
    pub entries: Vec<UsagePriceEntryConfig>,
}

/// Integer USD-tick rates. Token rates are per million tokens; media rates are
/// per explicitly reported unit. Omitted rates do not contribute an estimate.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UsagePriceEntryConfig {
    pub provider: String,
    pub model: String,
    pub input_per_million_usd_ticks: Option<u64>,
    pub output_per_million_usd_ticks: Option<u64>,
    pub reasoning_per_million_usd_ticks: Option<u64>,
    pub cache_per_million_usd_ticks: Option<u64>,
    pub image_per_unit_usd_ticks: Option<u64>,
    pub audio_per_unit_usd_ticks: Option<u64>,
    pub video_per_unit_usd_ticks: Option<u64>,
}

/// Immutable compiled price book.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsagePriceBookPlan {
    version: Arc<str>,
    entries: Vec<UsagePriceEntryPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UsagePriceEntryPlan {
    provider: Arc<str>,
    model: Arc<str>,
    input_per_million_usd_ticks: Option<u64>,
    output_per_million_usd_ticks: Option<u64>,
    reasoning_per_million_usd_ticks: Option<u64>,
    cache_per_million_usd_ticks: Option<u64>,
    image_per_unit_usd_ticks: Option<u64>,
    audio_per_unit_usd_ticks: Option<u64>,
    video_per_unit_usd_ticks: Option<u64>,
}

/// Usage quantities accepted by operator estimation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UsageAmounts {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub cache_tokens: Option<u64>,
    pub image_units: Option<u64>,
    pub audio_units: Option<u64>,
    pub video_units: Option<u64>,
}

impl UsagePriceBookPlan {
    pub(crate) fn compile(config: &UsagePriceBookConfig) -> Result<Self, &'static str> {
        let version = config.version.trim();
        if version.is_empty() || version.len() > 128 {
            return Err("usage price book version must contain 1 to 128 characters");
        }
        if config.entries.is_empty() || config.entries.len() > 4_096 {
            return Err("usage price book must contain 1 to 4096 entries");
        }
        let mut entries = Vec::with_capacity(config.entries.len());
        for entry in &config.entries {
            let provider = entry.provider.trim();
            let model = entry.model.trim();
            if provider.is_empty() || provider.len() > 128 || model.is_empty() || model.len() > 256
            {
                return Err("usage price entry provider/model is invalid");
            }
            if entries.iter().any(|candidate: &UsagePriceEntryPlan| {
                candidate.provider.as_ref() == provider && candidate.model.as_ref() == model
            }) {
                return Err("usage price book contains a duplicate provider/model entry");
            }
            if rates(entry).all(|rate| rate.is_none()) {
                return Err("usage price entry must declare at least one rate");
            }
            entries.push(UsagePriceEntryPlan {
                provider: Arc::from(provider),
                model: Arc::from(model),
                input_per_million_usd_ticks: entry.input_per_million_usd_ticks,
                output_per_million_usd_ticks: entry.output_per_million_usd_ticks,
                reasoning_per_million_usd_ticks: entry.reasoning_per_million_usd_ticks,
                cache_per_million_usd_ticks: entry.cache_per_million_usd_ticks,
                image_per_unit_usd_ticks: entry.image_per_unit_usd_ticks,
                audio_per_unit_usd_ticks: entry.audio_per_unit_usd_ticks,
                video_per_unit_usd_ticks: entry.video_per_unit_usd_ticks,
            });
        }
        Ok(Self {
            version: Arc::from(version),
            entries,
        })
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Estimate integer USD ticks using only explicitly declared rates.
    /// Per-million token terms are rounded down; media terms are per unit.
    #[must_use]
    pub fn estimate(&self, provider: &str, model: &str, usage: UsageAmounts) -> Option<u64> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.provider.as_ref() == provider && entry.model.as_ref() == model)?;
        let mut total = 0_u128;
        let mut matched = false;
        for (amount, rate) in [
            (usage.input_tokens, entry.input_per_million_usd_ticks),
            (usage.output_tokens, entry.output_per_million_usd_ticks),
            (
                usage.reasoning_tokens,
                entry.reasoning_per_million_usd_ticks,
            ),
            (usage.cache_tokens, entry.cache_per_million_usd_ticks),
        ] {
            if let (Some(amount), Some(rate)) = (amount, rate) {
                matched = true;
                let term = u128::from(amount).checked_mul(u128::from(rate))? / 1_000_000;
                total = total.checked_add(term)?;
            }
        }
        for (amount, rate) in [
            (usage.image_units, entry.image_per_unit_usd_ticks),
            (usage.audio_units, entry.audio_per_unit_usd_ticks),
            (usage.video_units, entry.video_per_unit_usd_ticks),
        ] {
            if let (Some(amount), Some(rate)) = (amount, rate) {
                matched = true;
                let term = u128::from(amount).checked_mul(u128::from(rate))?;
                total = total.checked_add(term)?;
            }
        }
        if matched {
            u64::try_from(total).ok()
        } else {
            None
        }
    }
}

fn rates(entry: &UsagePriceEntryConfig) -> impl Iterator<Item = Option<u64>> + '_ {
    [
        entry.input_per_million_usd_ticks,
        entry.output_per_million_usd_ticks,
        entry.reasoning_per_million_usd_ticks,
        entry.cache_per_million_usd_ticks,
        entry.image_per_unit_usd_ticks,
        entry.audio_per_unit_usd_ticks,
        entry.video_per_unit_usd_ticks,
    ]
    .into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_only_explicit_matching_rates() {
        let plan = UsagePriceBookPlan::compile(&UsagePriceBookConfig {
            version: "operator-2026-08-22".to_owned(),
            entries: vec![UsagePriceEntryConfig {
                provider: "provider".to_owned(),
                model: "model".to_owned(),
                input_per_million_usd_ticks: Some(2_000_000),
                image_per_unit_usd_ticks: Some(5),
                ..UsagePriceEntryConfig::default()
            }],
        })
        .expect("price book");
        assert_eq!(
            plan.estimate(
                "provider",
                "model",
                UsageAmounts {
                    input_tokens: Some(3),
                    image_units: Some(2),
                    ..UsageAmounts::default()
                },
            ),
            Some(16)
        );
        assert_eq!(
            plan.estimate("other", "model", UsageAmounts::default()),
            None
        );
    }

    #[test]
    fn rejects_unversioned_empty_and_duplicate_entries() {
        assert!(UsagePriceBookPlan::compile(&UsagePriceBookConfig::default()).is_err());
        let duplicate = UsagePriceEntryConfig {
            provider: "provider".to_owned(),
            model: "model".to_owned(),
            input_per_million_usd_ticks: Some(1),
            ..UsagePriceEntryConfig::default()
        };
        assert!(UsagePriceBookPlan::compile(&UsagePriceBookConfig {
            version: "v1".to_owned(),
            entries: vec![duplicate.clone(), duplicate],
        })
        .is_err());
    }

    #[test]
    fn configuration_rejects_price_entries_for_unknown_upstreams() {
        let error = crate::compile_yaml(
            "price-book.yaml",
            r#"
version: 2
upstreams: {known: {url: http://127.0.0.1:1}}
usage_price_book:
  version: v1
  entries:
    - provider: missing
      model: model
      input_per_million_usd_ticks: 1
"#,
        )
        .expect_err("unknown upstream rejected");
        assert!(matches!(
            error,
            crate::ConfigError::MissingReference {
                kind: "upstream",
                ..
            }
        ));
    }
}
