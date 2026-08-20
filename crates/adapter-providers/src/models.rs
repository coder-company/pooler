//! Bounded normalization of provider model-discovery responses.

use std::collections::{BTreeMap, BTreeSet};

use pooler_core::{Capability, CapabilitySet, ModelId};
use pooler_model_catalog::{
    DiscoveredModel as CatalogDiscoveredModel, DiscoveryResponse as CatalogDiscoveryResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// A provider model normalized without inventing unsupported capabilities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveredModel {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_length: Option<u64>,
    pub capabilities: CapabilitySet,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// Capability hints returned by Antigravity's pinned compatibility endpoint.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityModelHints {
    pub web_search_models: BTreeSet<String>,
}

/// Bounded model discovery parse error. Raw provider bytes are never retained.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelDiscoveryError {
    #[error("provider model response exceeds the {limit}-byte bound")]
    BodyTooLarge { limit: usize },
    #[error("provider model response is not valid JSON")]
    InvalidJson,
    #[error("provider model response does not contain the expected list")]
    InvalidShape,
    #[error("provider model response exceeds the {limit}-model bound")]
    TooManyModels { limit: usize },
    #[error("provider model entry {index} is invalid")]
    InvalidModel { index: usize },
    #[error("provider model identifier cannot enter the shared catalog")]
    InvalidCatalogIdentifier,
}

impl TryFrom<DiscoveredModel> for CatalogDiscoveredModel {
    type Error = ModelDiscoveryError;

    fn try_from(model: DiscoveredModel) -> Result<Self, Self::Error> {
        let id =
            ModelId::new(model.id).map_err(|_| ModelDiscoveryError::InvalidCatalogIdentifier)?;
        let mut converted = Self::new(id, model.capabilities);
        if let Some(display_name) = model.display_name {
            converted = converted.with_display_name(display_name);
        }
        Ok(converted)
    }
}

/// Convert provider parser output directly into the shared catalog discovery DTO.
pub fn try_into_catalog_response(
    models: Vec<DiscoveredModel>,
    revision: Option<String>,
) -> Result<CatalogDiscoveryResponse, ModelDiscoveryError> {
    let models = models
        .into_iter()
        .map(CatalogDiscoveredModel::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let mut response = CatalogDiscoveryResponse::new(models);
    if let Some(revision) = revision {
        response = response.with_revision(revision);
    }
    Ok(response)
}

/// Resource bounds for provider catalog parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderModelParser {
    max_body_bytes: usize,
    max_models: usize,
    max_string_bytes: usize,
}

impl Default for ProviderModelParser {
    fn default() -> Self {
        Self {
            max_body_bytes: 2 * 1024 * 1024,
            max_models: 4096,
            max_string_bytes: 1024,
        }
    }
}

impl ProviderModelParser {
    /// Construct with explicit body, item-count, and per-string bounds.
    #[must_use]
    pub const fn new(max_body_bytes: usize, max_models: usize, max_string_bytes: usize) -> Self {
        Self {
            max_body_bytes,
            max_models,
            max_string_bytes,
        }
    }

    /// Parse an OpenAI-style `data[]` list, including Kimi capability extensions.
    pub fn parse_openai_list(
        &self,
        body: &[u8],
    ) -> Result<Vec<DiscoveredModel>, ModelDiscoveryError> {
        let value = self.parse_json(body)?;
        let models = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or(ModelDiscoveryError::InvalidShape)?;
        self.check_model_count(models.len())?;
        models
            .iter()
            .enumerate()
            .map(|(index, value)| self.parse_openai_model(index, value))
            .collect()
    }

    /// Parse the Kimi Open Platform list and attach capabilities established
    /// by Kimi's Chat Completions surface in addition to per-model extensions.
    pub fn parse_kimi_list(
        &self,
        body: &[u8],
    ) -> Result<Vec<DiscoveredModel>, ModelDiscoveryError> {
        let mut models = self.parse_openai_list(body)?;
        for model in &mut models {
            model.capabilities.insert(Capability::Text);
            model.capabilities.insert(Capability::Streaming);
            model.capabilities.insert(Capability::Usage);
        }
        Ok(models)
    }

    /// Parse a Vertex publisher-model catalog snapshot.
    ///
    /// Google catalog exports have used both `publisherModels[]` and `models[]`;
    /// the parser accepts those explicit containers and no arbitrary recursive scan.
    pub fn parse_vertex_catalog(
        &self,
        body: &[u8],
    ) -> Result<Vec<DiscoveredModel>, ModelDiscoveryError> {
        let value = self.parse_json(body)?;
        let models = value
            .get("publisherModels")
            .or_else(|| value.get("models"))
            .and_then(Value::as_array)
            .ok_or(ModelDiscoveryError::InvalidShape)?;
        self.check_model_count(models.len())?;
        models
            .iter()
            .enumerate()
            .map(|(index, value)| self.parse_vertex_model(index, value))
            .collect()
    }

    /// Parse only the capability hints returned by the pinned Antigravity endpoint.
    pub fn parse_antigravity_hints(
        &self,
        body: &[u8],
    ) -> Result<AntigravityModelHints, ModelDiscoveryError> {
        let value = self.parse_json(body)?;
        let Some(models) = value.get("webSearchModelIds") else {
            return Ok(AntigravityModelHints::default());
        };
        let models = models.as_array().ok_or(ModelDiscoveryError::InvalidShape)?;
        self.check_model_count(models.len())?;
        let mut web_search_models = BTreeSet::new();
        for (index, model) in models.iter().enumerate() {
            let model = model
                .as_str()
                .and_then(|value| self.bounded_identifier(value))
                .ok_or(ModelDiscoveryError::InvalidModel { index })?;
            web_search_models.insert(model.to_ascii_lowercase());
        }
        Ok(AntigravityModelHints { web_search_models })
    }

    fn parse_json(&self, body: &[u8]) -> Result<Value, ModelDiscoveryError> {
        if body.len() > self.max_body_bytes {
            return Err(ModelDiscoveryError::BodyTooLarge {
                limit: self.max_body_bytes,
            });
        }
        serde_json::from_slice(body).map_err(|_| ModelDiscoveryError::InvalidJson)
    }

    const fn check_model_count(&self, observed: usize) -> Result<(), ModelDiscoveryError> {
        if observed > self.max_models {
            Err(ModelDiscoveryError::TooManyModels {
                limit: self.max_models,
            })
        } else {
            Ok(())
        }
    }

    fn parse_openai_model(
        &self,
        index: usize,
        value: &Value,
    ) -> Result<DiscoveredModel, ModelDiscoveryError> {
        let object = value
            .as_object()
            .ok_or(ModelDiscoveryError::InvalidModel { index })?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .and_then(|value| self.bounded_identifier(value))
            .ok_or(ModelDiscoveryError::InvalidModel { index })?
            .to_owned();
        let display_name = self.optional_bounded_string(object.get("display_name"), index)?;
        let owned_by = self.optional_bounded_string(object.get("owned_by"), index)?;
        let created = object.get("created").and_then(Value::as_u64);
        let context_length = object
            .get("context_length")
            .or_else(|| object.get("max_context_length"))
            .and_then(Value::as_u64);
        let mut capabilities = CapabilitySet::new();
        let mut attributes = BTreeMap::new();
        if object
            .get("supports_image_in")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            capabilities.insert(Capability::Images);
        }
        if object
            .get("supports_reasoning")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            capabilities.insert(Capability::Reasoning);
        }
        if object
            .get("supports_function_calling")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            capabilities.insert(Capability::FunctionCalling);
            capabilities.insert(Capability::Tools);
        }
        if object
            .get("supports_video_in")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            attributes.insert("supports_video_input".to_owned(), "true".to_owned());
        }
        Ok(DiscoveredModel {
            id,
            display_name,
            owned_by,
            created,
            context_length,
            capabilities,
            attributes,
        })
    }

    fn parse_vertex_model(
        &self,
        index: usize,
        value: &Value,
    ) -> Result<DiscoveredModel, ModelDiscoveryError> {
        let object = value
            .as_object()
            .ok_or(ModelDiscoveryError::InvalidModel { index })?;
        let full_name = object
            .get("name")
            .and_then(Value::as_str)
            .and_then(|value| self.bounded_string(value))
            .ok_or(ModelDiscoveryError::InvalidModel { index })?;
        let id = full_name
            .rsplit_once("/models/")
            .map_or(full_name, |(_, id)| id);
        let id = self
            .bounded_identifier(id)
            .ok_or(ModelDiscoveryError::InvalidModel { index })?
            .to_owned();
        let display_name = self.optional_bounded_string(
            object
                .get("displayName")
                .or_else(|| object.get("display_name")),
            index,
        )?;
        let mut capabilities = CapabilitySet::new();
        let mut attributes = BTreeMap::new();
        if let Some(actions) = object.get("supportedActions") {
            let actions = actions
                .as_array()
                .ok_or(ModelDiscoveryError::InvalidModel { index })?;
            if actions.len() > 64 {
                return Err(ModelDiscoveryError::InvalidModel { index });
            }
            let mut normalized_actions = Vec::with_capacity(actions.len());
            for action in actions {
                let action = action
                    .as_str()
                    .and_then(|value| self.bounded_string(value))
                    .ok_or(ModelDiscoveryError::InvalidModel { index })?;
                match action.to_ascii_lowercase().as_str() {
                    "generatecontent" => capabilities.insert(Capability::Text),
                    "streamgeneratecontent" => {
                        capabilities.insert(Capability::Text);
                        capabilities.insert(Capability::Streaming);
                        capabilities.insert(Capability::Sse);
                    }
                    "embedcontent" => capabilities.insert(Capability::Embeddings),
                    "predict" if id.to_ascii_lowercase().contains("imagen") => {
                        capabilities.insert(Capability::Images);
                    }
                    _ => {}
                }
                normalized_actions.push(action.to_owned());
            }
            if !normalized_actions.is_empty() {
                attributes.insert("supported_actions".to_owned(), normalized_actions.join(","));
            }
        }
        let owned_by = publisher_from_name(full_name).map(str::to_owned);
        Ok(DiscoveredModel {
            id,
            display_name,
            owned_by,
            created: None,
            context_length: object
                .get("contextWindow")
                .or_else(|| object.get("context_window"))
                .and_then(Value::as_u64),
            capabilities,
            attributes,
        })
    }

    fn optional_bounded_string(
        &self,
        value: Option<&Value>,
        index: usize,
    ) -> Result<Option<String>, ModelDiscoveryError> {
        let Some(value) = value else {
            return Ok(None);
        };
        let value = value
            .as_str()
            .and_then(|value| self.bounded_string(value))
            .ok_or(ModelDiscoveryError::InvalidModel { index })?;
        Ok(Some(value.to_owned()))
    }

    fn bounded_string<'a>(&self, value: &'a str) -> Option<&'a str> {
        let value = value.trim();
        (!value.is_empty()
            && value.len() <= self.max_string_bytes
            && !value.chars().any(char::is_control))
        .then_some(value)
    }

    fn bounded_identifier<'a>(&self, value: &'a str) -> Option<&'a str> {
        self.bounded_string(value).filter(|value| {
            value.len() <= 256
                && !value
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        })
    }
}

fn publisher_from_name(value: &str) -> Option<&str> {
    let suffix = value
        .strip_prefix("publishers/")
        .or_else(|| value.split_once("/publishers/").map(|(_, suffix)| suffix))?;
    let (publisher, _) = suffix.split_once('/')?;
    (!publisher.is_empty()).then_some(publisher)
}
