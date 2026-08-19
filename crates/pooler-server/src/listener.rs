//! Listener preparation contract used by startup and reload.

use std::{future::Future, pin::Pin, sync::Arc};

use pooler_core::ConfigGeneration;
use tokio_util::sync::CancellationToken;

use crate::ConfigSnapshot;

/// The future returned by a listener preparer.
pub type ListenerPreparationFuture<'a, L, E> =
    Pin<Box<dyn Future<Output = Result<L, E>> + Send + 'a>>;

/// A listener set prepared against one configuration generation.
pub struct PreparedListeners<L> {
    generation: ConfigGeneration,
    listeners: Arc<L>,
}

impl<L> PreparedListeners<L> {
    /// Create a prepared listener set.
    #[must_use]
    pub fn new(generation: ConfigGeneration, listeners: L) -> Self {
        Self {
            generation,
            listeners: Arc::new(listeners),
        }
    }

    /// Return the configuration generation used for preparation.
    #[must_use]
    pub const fn generation(&self) -> ConfigGeneration {
        self.generation
    }

    /// Borrow the prepared listeners.
    #[must_use]
    pub fn listeners(&self) -> &L {
        &self.listeners
    }
}

impl<L> Clone for PreparedListeners<L> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            listeners: Arc::clone(&self.listeners),
        }
    }
}

/// Prepares listeners without publishing them.
pub trait ListenerPreparer<C>: Send + Sync + 'static {
    /// The prepared listener state owned by the server.
    type Prepared: Send + Sync + 'static;
    /// The preparation/validation error.
    type Error: Send + Sync + 'static;

    /// Prepare listeners for one immutable config snapshot.
    fn prepare(
        &self,
        snapshot: Arc<ConfigSnapshot<C>>,
        cancellation: CancellationToken,
    ) -> ListenerPreparationFuture<'_, Self::Prepared, Self::Error>;
}
