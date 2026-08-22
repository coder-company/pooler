//! Bounded projections and exports for the historical usage ledger.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use pooler_store::{CostProvenance, RetentionPolicy, UsageRecord};
use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_USAGE_LIMIT: usize = 100;
const MAX_USAGE_LIMIT: usize = 1_000;
const MAX_USAGE_EXPORT: usize = 16_384;
const MAX_AGGREGATE_SERIES: usize = 256;
const MAX_GROUPING_DIMENSIONS: usize = 6;

#[derive(Default)]
struct UsageQuery {
    cursor: Option<u64>,
    limit: Option<usize>,
    since: Option<u64>,
    until: Option<u64>,
    route: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    account: Option<String>,
    result_class: Option<String>,
    service_tier: Option<String>,
    group_by: Vec<GroupBy>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GroupBy {
    Route,
    Provider,
    PublicModel,
    UpstreamModel,
    Account,
    ResultClass,
    ServiceTier,
    CostProvenance,
    PriceBookVersion,
    ConfigurationGeneration,
    CatalogGeneration,
}

impl GroupBy {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "route" => Some(Self::Route),
            "provider" => Some(Self::Provider),
            "public_model" => Some(Self::PublicModel),
            "upstream_model" | "model" => Some(Self::UpstreamModel),
            "account" => Some(Self::Account),
            "result_class" => Some(Self::ResultClass),
            "service_tier" => Some(Self::ServiceTier),
            "cost_provenance" => Some(Self::CostProvenance),
            "price_book_version" => Some(Self::PriceBookVersion),
            "configuration_generation" => Some(Self::ConfigurationGeneration),
            "catalog_generation" => Some(Self::CatalogGeneration),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::Provider => "provider",
            Self::PublicModel => "public_model",
            Self::UpstreamModel => "upstream_model",
            Self::Account => "account",
            Self::ResultClass => "result_class",
            Self::ServiceTier => "service_tier",
            Self::CostProvenance => "cost_provenance",
            Self::PriceBookVersion => "price_book_version",
            Self::ConfigurationGeneration => "configuration_generation",
            Self::CatalogGeneration => "catalog_generation",
        }
    }

    fn value(self, record: &UsageRecord) -> String {
        match self {
            Self::Route => record.route.clone(),
            Self::Provider => record.provider.clone().unwrap_or_default(),
            Self::PublicModel => record.public_model.clone().unwrap_or_default(),
            Self::UpstreamModel => record.upstream_model.clone().unwrap_or_default(),
            Self::Account => record.account_pseudonym.clone().unwrap_or_default(),
            Self::ResultClass => record.result_class.clone(),
            Self::ServiceTier => record.service_tier.clone().unwrap_or_default(),
            Self::CostProvenance => provenance_name(record.cost_provenance).to_owned(),
            Self::PriceBookVersion => record.price_book_version.clone().unwrap_or_default(),
            Self::ConfigurationGeneration => record.configuration_generation.to_string(),
            Self::CatalogGeneration => record
                .catalog_generation
                .map_or_else(String::new, |value| value.to_string()),
        }
    }
}

#[derive(Default, Serialize)]
struct UsageTotals {
    records: u64,
    input_tokens: u64,
    output_tokens: u64,
    reasoning_tokens: u64,
    cache_tokens: u64,
    image_units: u64,
    audio_units: u64,
    video_units: u64,
    latency_ms: u64,
    ttft_ms: u64,
    ttft_records: u64,
    cost_in_usd_ticks: u64,
    provider_reported_cost_records: u64,
    operator_estimated_cost_records: u64,
    unknown_cost_records: u64,
}

impl UsageTotals {
    fn record(&mut self, record: &UsageRecord) {
        self.records = self.records.saturating_add(1);
        self.input_tokens = self
            .input_tokens
            .saturating_add(record.input_tokens.unwrap_or_default());
        self.output_tokens = self
            .output_tokens
            .saturating_add(record.output_tokens.unwrap_or_default());
        self.reasoning_tokens = self
            .reasoning_tokens
            .saturating_add(record.reasoning_tokens.unwrap_or_default());
        self.cache_tokens = self
            .cache_tokens
            .saturating_add(record.cache_tokens.unwrap_or_default());
        self.image_units = self
            .image_units
            .saturating_add(record.image_units.unwrap_or_default());
        self.audio_units = self
            .audio_units
            .saturating_add(record.audio_units.unwrap_or_default());
        self.video_units = self
            .video_units
            .saturating_add(record.video_units.unwrap_or_default());
        self.latency_ms = self.latency_ms.saturating_add(record.latency_ms);
        if let Some(ttft_ms) = record.ttft_ms {
            self.ttft_ms = self.ttft_ms.saturating_add(ttft_ms);
            self.ttft_records = self.ttft_records.saturating_add(1);
        }
        if let Some(cost) = record.cost_in_usd_ticks {
            self.cost_in_usd_ticks = self.cost_in_usd_ticks.saturating_add(cost);
        }
        match record.cost_provenance {
            CostProvenance::ProviderReported => {
                self.provider_reported_cost_records =
                    self.provider_reported_cost_records.saturating_add(1);
            }
            CostProvenance::OperatorEstimated => {
                self.operator_estimated_cost_records =
                    self.operator_estimated_cost_records.saturating_add(1);
            }
            CostProvenance::Unknown => {
                self.unknown_cost_records = self.unknown_cost_records.saturating_add(1);
            }
        }
    }
}

pub(crate) fn usage_list(
    records: Vec<UsageRecord>,
    query: Option<&str>,
    retention: RetentionPolicy,
    export: bool,
) -> Value {
    let query = parse_query(query);
    let mut records = filtered(records, &query);
    if let Some(cursor) = query.cursor {
        records.retain(|record| record.id < cursor);
    }
    records.sort_by_key(|record| Reverse(record.id));
    let limit = query
        .limit
        .unwrap_or(if export {
            MAX_USAGE_EXPORT
        } else {
            DEFAULT_USAGE_LIMIT
        })
        .min(if export {
            MAX_USAGE_EXPORT
        } else {
            MAX_USAGE_LIMIT
        });
    let has_more = records.len() > limit;
    records.truncate(limit);
    let next_cursor = has_more
        .then(|| records.last())
        .flatten()
        .map(|record| record.id);
    json!({
        "schema_version": 1,
        "records": records,
        "limit": limit,
        "next_cursor": next_cursor,
        "retention": {
            "max_records": retention.max_usage_records,
            "ttl_ms": retention.usage_history_ttl_ms,
            "max_aggregate_series": MAX_AGGREGATE_SERIES,
        },
    })
}

pub(crate) fn usage_aggregate(records: Vec<UsageRecord>, query: Option<&str>) -> Value {
    let mut query = parse_query(query);
    if query.group_by.is_empty() {
        query.group_by = vec![
            GroupBy::Route,
            GroupBy::Provider,
            GroupBy::UpstreamModel,
            GroupBy::ResultClass,
            GroupBy::CostProvenance,
            GroupBy::PriceBookVersion,
        ];
    }
    let mut records = filtered(records, &query);
    records.sort_by_key(|record| Reverse(record.id));
    let mut series = BTreeMap::<Vec<(String, String)>, UsageTotals>::new();
    let mut dropped_series_records = 0_u64;
    for record in records {
        let key = query
            .group_by
            .iter()
            .map(|dimension| (dimension.name().to_owned(), dimension.value(&record)))
            .collect::<Vec<_>>();
        if !series.contains_key(&key) && series.len() >= MAX_AGGREGATE_SERIES {
            dropped_series_records = dropped_series_records.saturating_add(1);
            continue;
        }
        series.entry(key).or_default().record(&record);
    }
    let series = series
        .into_iter()
        .map(|(dimensions, totals)| {
            json!({
                "dimensions": dimensions.into_iter().collect::<BTreeMap<_, _>>(),
                "totals": totals,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": 1,
        "group_by": query.group_by.iter().map(|value| value.name()).collect::<Vec<_>>(),
        "series": series,
        "max_series": MAX_AGGREGATE_SERIES,
        "dropped_series_records": dropped_series_records,
    })
}

pub(crate) fn usage_prometheus(records: Vec<UsageRecord>, query: Option<&str>) -> String {
    const METRICS: [(&str, &str, &str); 12] = [
        (
            "pooler_usage_records",
            "records",
            "Completed retained requests.",
        ),
        (
            "pooler_usage_input_tokens",
            "input_tokens",
            "Reported input tokens.",
        ),
        (
            "pooler_usage_output_tokens",
            "output_tokens",
            "Reported output tokens.",
        ),
        (
            "pooler_usage_reasoning_tokens",
            "reasoning_tokens",
            "Reported reasoning tokens.",
        ),
        (
            "pooler_usage_cache_tokens",
            "cache_tokens",
            "Reported cache tokens.",
        ),
        (
            "pooler_usage_image_units",
            "image_units",
            "Reported image units.",
        ),
        (
            "pooler_usage_audio_units",
            "audio_units",
            "Reported audio units.",
        ),
        (
            "pooler_usage_video_units",
            "video_units",
            "Reported video units.",
        ),
        (
            "pooler_usage_latency_milliseconds",
            "latency_ms",
            "Completed request latency in milliseconds.",
        ),
        (
            "pooler_usage_ttft_milliseconds",
            "ttft_ms",
            "Reported time to first event in milliseconds.",
        ),
        (
            "pooler_usage_ttft_observations",
            "ttft_records",
            "Requests with a time-to-first-event observation.",
        ),
        (
            "pooler_usage_cost_usd_ticks",
            "cost_in_usd_ticks",
            "Reported or versioned estimated USD ticks.",
        ),
    ];
    let aggregate = usage_aggregate(records, query);
    let mut output = String::new();
    for (name, _, help) in METRICS {
        output.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
    }
    let Some(series) = aggregate["series"].as_array() else {
        return output;
    };
    for item in series {
        let labels = prometheus_labels(&item["dimensions"]);
        let totals = &item["totals"];
        for (name, field, _) in METRICS {
            let value = totals[field].as_u64().unwrap_or_default();
            output.push_str(&format!("{name}{labels} {value}\n"));
        }
    }
    output
}

/// Render an OTLP/JSON `ExportMetricsServiceRequest` using the proto3 JSON
/// mapping. 64-bit integers are decimal strings and enum values are integers.
pub(crate) fn usage_otlp_json(records: Vec<UsageRecord>, query: Option<&str>) -> Value {
    let aggregate = usage_aggregate(records, query);
    let now_nanos = current_time_nanos().to_string();
    let series = aggregate["series"].as_array().cloned().unwrap_or_default();
    let metrics = [
        ("pooler.usage.records", "records", "{request}"),
        ("pooler.usage.input_tokens", "input_tokens", "{token}"),
        ("pooler.usage.output_tokens", "output_tokens", "{token}"),
        (
            "pooler.usage.reasoning_tokens",
            "reasoning_tokens",
            "{token}",
        ),
        ("pooler.usage.cache_tokens", "cache_tokens", "{token}"),
        ("pooler.usage.image_units", "image_units", "{unit}"),
        ("pooler.usage.audio_units", "audio_units", "{unit}"),
        ("pooler.usage.video_units", "video_units", "{unit}"),
        ("pooler.usage.latency", "latency_ms", "ms"),
        ("pooler.usage.ttft", "ttft_ms", "ms"),
        (
            "pooler.usage.ttft_observations",
            "ttft_records",
            "{request}",
        ),
        ("pooler.usage.cost", "cost_in_usd_ticks", "{usd_tick}"),
    ]
    .into_iter()
    .map(|(name, field, unit)| {
        let data_points = series
            .iter()
            .map(|item| {
                let value = item["totals"][field].as_u64().unwrap_or_default();
                let mut point = json!({
                    "attributes": otlp_attributes(&item["dimensions"]),
                    "timeUnixNano": now_nanos,
                });
                let object = point.as_object_mut().expect("data point is an object");
                if i64::try_from(value).is_ok() {
                    object.insert("asInt".to_owned(), Value::String(value.to_string()));
                } else {
                    object.insert("asDouble".to_owned(), json!(value as f64));
                }
                point
            })
            .collect::<Vec<_>>();
        json!({
            "name": name,
            "unit": unit,
            "gauge": {"dataPoints": data_points}
        })
    })
    .collect::<Vec<_>>();
    json!({
        "resourceMetrics": [{
            "resource": {"attributes": [{
                "key": "service.name",
                "value": {"stringValue": "pooler"}
            }]},
            "scopeMetrics": [{
                "scope": {"name": "pooler.usage", "version": env!("CARGO_PKG_VERSION")},
                "metrics": metrics,
            }]
        }]
    })
}

fn parse_query(query: Option<&str>) -> UsageQuery {
    let mut parsed = UsageQuery::default();
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "cursor" => parsed.cursor = value.parse().ok(),
            "limit" => parsed.limit = value.parse().ok(),
            "since" => parsed.since = value.parse().ok(),
            "until" => parsed.until = value.parse().ok(),
            "route" if value.len() <= 128 => parsed.route = Some(value),
            "provider" if value.len() <= 256 => parsed.provider = Some(value),
            "model" if value.len() <= 256 => parsed.model = Some(value),
            "account" if value.len() <= 256 => parsed.account = Some(value),
            "result_class" if value.len() <= 64 => parsed.result_class = Some(value),
            "service_tier" if value.len() <= 256 => parsed.service_tier = Some(value),
            "group_by" => {
                parsed.group_by = value
                    .split(',')
                    .filter_map(GroupBy::parse)
                    .take(MAX_GROUPING_DIMENSIONS)
                    .collect();
                parsed.group_by.sort();
                parsed.group_by.dedup();
            }
            _ => {}
        }
    }
    parsed
}

fn filtered(mut records: Vec<UsageRecord>, query: &UsageQuery) -> Vec<UsageRecord> {
    records.retain(|record| {
        query.since.is_none_or(|since| record.recorded_at >= since)
            && query.until.is_none_or(|until| record.recorded_at <= until)
            && query
                .route
                .as_ref()
                .is_none_or(|value| &record.route == value)
            && query
                .provider
                .as_ref()
                .is_none_or(|value| record.provider.as_ref() == Some(value))
            && query.model.as_ref().is_none_or(|value| {
                record.public_model.as_ref() == Some(value)
                    || record.upstream_model.as_ref() == Some(value)
            })
            && query
                .account
                .as_ref()
                .is_none_or(|value| record.account_pseudonym.as_ref() == Some(value))
            && query
                .result_class
                .as_ref()
                .is_none_or(|value| &record.result_class == value)
            && query
                .service_tier
                .as_ref()
                .is_none_or(|value| record.service_tier.as_ref() == Some(value))
    });
    records
}

fn provenance_name(value: CostProvenance) -> &'static str {
    match value {
        CostProvenance::ProviderReported => "provider_reported",
        CostProvenance::OperatorEstimated => "operator_estimated",
        CostProvenance::Unknown => "unknown",
    }
}

fn prometheus_labels(dimensions: &Value) -> String {
    let labels = dimensions
        .as_object()
        .into_iter()
        .flat_map(serde_json::Map::iter)
        .filter_map(|(key, value)| Some((key, value.as_str()?)))
        .map(|(key, value)| format!("{key}=\"{}\"", escape_prometheus(value)))
        .collect::<Vec<_>>();
    if labels.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", labels.join(","))
    }
}

fn escape_prometheus(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn otlp_attributes(dimensions: &Value) -> Vec<Value> {
    dimensions
        .as_object()
        .into_iter()
        .flat_map(serde_json::Map::iter)
        .filter_map(|(key, value)| {
            Some(json!({
                "key": key,
                "value": {"stringValue": value.as_str()?},
            }))
        })
        .collect()
}

fn current_time_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: u64, route: &str, provider: &str) -> UsageRecord {
        let mut record = UsageRecord::new(id, format!("request-{id}"), route, "success");
        record.id = id;
        record.provider = Some(provider.to_owned());
        record.upstream_model = Some("model".to_owned());
        record.input_tokens = Some(id);
        record.latency_ms = id * 10;
        record
    }

    #[test]
    fn list_filters_and_paginates_descending() {
        let value = usage_list(
            vec![
                record(1, "a", "p"),
                record(2, "b", "p"),
                record(3, "a", "q"),
            ],
            Some("route=a&limit=1"),
            RetentionPolicy::default(),
            false,
        );
        assert_eq!(value["records"][0]["id"], 3);
        assert_eq!(value["next_cursor"], 3);
    }

    #[test]
    fn aggregation_is_dimensioned_and_bounded() {
        let value = usage_aggregate(
            vec![record(1, "a", "p"), record(2, "a", "p")],
            Some("group_by=route,provider"),
        );
        assert_eq!(value["series"].as_array().expect("series").len(), 1);
        assert_eq!(value["series"][0]["totals"]["input_tokens"], 3);
        let bounded = usage_aggregate(
            (0..300)
                .map(|index| record(index, &format!("route-{index}"), "provider"))
                .collect(),
            Some("group_by=route"),
        );
        assert_eq!(
            bounded["series"].as_array().expect("bounded series").len(),
            MAX_AGGREGATE_SERIES
        );
        assert_eq!(bounded["dropped_series_records"], 44);
    }

    #[test]
    fn exports_have_prometheus_and_otlp_shapes() {
        let records = vec![record(1, "a", "p")];
        assert!(usage_prometheus(records.clone(), None).contains("pooler_usage_input_tokens"));
        let otlp = usage_otlp_json(records, None);
        assert_eq!(
            otlp["resourceMetrics"][0]["scopeMetrics"][0]["scope"]["name"],
            "pooler.usage"
        );
        let metrics = otlp["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .expect("OTLP metrics");
        assert!(!metrics.is_empty());

        let mut huge = record(2, "a", "p");
        huge.input_tokens = Some(u64::MAX);
        let huge = usage_otlp_json(vec![huge], None);
        let input_metric = huge["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .expect("OTLP metrics")
            .iter()
            .find(|metric| metric["name"] == "pooler.usage.input_tokens")
            .expect("input metric");
        assert!(input_metric["gauge"]["dataPoints"][0]["asDouble"].is_number());
    }
}
