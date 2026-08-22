//! Process lifecycle and component wiring for Pooler.
//!
//! The server deliberately does not own the configuration parser.  A
//! [`ConfigStore`] stores the immutable value produced by `pooler-config`, and
//! gives each caller an [`ConfigSnapshot`] containing the generation that was
//! current when it was admitted.  This keeps a reload from changing the
//! configuration observed by an in-flight request.

mod catalog_runtime;
mod config_management;
mod config_store;
mod http_runtime;
mod lifecycle;
mod listener;
mod management;
mod management_ui;
mod model_facts_refresh;
mod server;
mod tls;

pub use catalog_runtime::{
    merged_model_catalog_value, merged_model_ids, CatalogFetchFuture, CatalogFetcherRegistration,
    CatalogRuntime, CatalogRuntimeError, FetchedCatalog, ProviderCatalogFetcher,
};
pub use config_store::{ConfigSnapshot, ConfigStore, ConfigStoreError};
pub use http_runtime::{HttpProxyServer, HttpProxyServerError, HttpReloadOutcome, ListenerAddress};
pub use lifecycle::{Lifecycle, LifecycleError, LifecycleState};
pub use listener::{ListenerPreparationFuture, ListenerPreparer, PreparedListeners};
pub use management::{
    ActiveCounts, ActiveGuard, ManagementApi, ManagementHttpServer, ManagementResponse,
    ManagementServerError,
};
pub use model_facts_refresh::{fetch_model_facts, project_model_facts, ModelFactsRefreshError};
pub use pooler_core::ConfigGeneration;
pub use server::{ReloadError, ReloadOutcome, Server, ServerError};

/// Select a validated Pooler-managed sidecar when one exists, otherwise the
/// operator-authored source. Existing sidecars must be owner-private regular
/// files with Pooler's generated-file marker.
pub fn managed_configuration_source(
    source: impl AsRef<std::path::Path>,
) -> std::io::Result<std::path::PathBuf> {
    config_management::serving_source(source).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed configuration source is unsafe",
        )
    })
}

// Re-export the source/config crates used by this crate.  Keeping the server
// generic over its compiled configuration avoids coupling process lifecycle
// to a particular route-plan representation while still making the intended
// integration explicit to downstream users.
pub use pooler_config;
pub use pooler_core;
