//! Process lifecycle and component wiring for Pooler.
//!
//! The server deliberately does not own the configuration parser.  A
//! [`ConfigStore`] stores the immutable value produced by `pooler-config`, and
//! gives each caller an [`ConfigSnapshot`] containing the generation that was
//! current when it was admitted.  This keeps a reload from changing the
//! configuration observed by an in-flight request.

mod config_store;
mod http_runtime;
mod lifecycle;
mod listener;
mod management;
mod server;

pub use config_store::{ConfigSnapshot, ConfigStore, ConfigStoreError};
pub use http_runtime::{HttpProxyServer, HttpProxyServerError, HttpReloadOutcome, ListenerAddress};
pub use lifecycle::{Lifecycle, LifecycleError, LifecycleState};
pub use listener::{ListenerPreparationFuture, ListenerPreparer, PreparedListeners};
pub use management::{
    ActiveCounts, ActiveGuard, ManagementApi, ManagementHttpServer, ManagementResponse,
    ManagementServerError,
};
pub use pooler_core::ConfigGeneration;
pub use server::{ReloadError, ReloadOutcome, Server, ServerError};

// Re-export the source/config crates used by this crate.  Keeping the server
// generic over its compiled configuration avoids coupling process lifecycle
// to a particular route-plan representation while still making the intended
// integration explicit to downstream users.
pub use pooler_config;
pub use pooler_core;
