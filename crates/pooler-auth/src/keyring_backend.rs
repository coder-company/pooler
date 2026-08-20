//! Optional platform keyring access for `keyring:` secret references.
//!
//! The system implementation is intentionally small and synchronous.  Linux
//! uses the kernel keyring rather than Secret Service so a missing entry fails
//! immediately instead of trying to unlock an interactive desktop session.
//! Tests and embedders can inject a provider without touching a process-global
//! keyring builder.

use std::sync::Arc;

use crate::{SecretBackend, SecretError, SecretValue};

/// A narrow keyring lookup seam used by [`OsKeyringBackend`].
pub trait KeyringProvider: Send + Sync {
    /// Look up one service/account pair without returning source diagnostics.
    fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, SecretError>;
}

/// Resolve keyring references through an operating-system credential store.
///
/// The backend is available only when the `os-keyring` feature is enabled and
/// the current target has a native implementation.  Otherwise it returns a
/// sanitized unavailable error.  No fallback to environment variables,
/// files, command execution, or literals is performed.
#[derive(Clone)]
pub struct OsKeyringBackend {
    provider: Arc<dyn KeyringProvider>,
}

impl OsKeyringBackend {
    /// Construct a backend using the configured platform keyring.
    #[must_use]
    pub fn new() -> Self {
        Self::with_provider(PlatformKeyring)
    }

    /// Construct a backend with an explicitly injected provider.
    #[must_use]
    pub fn with_provider(provider: impl KeyringProvider + 'static) -> Self {
        Self {
            provider: Arc::new(provider),
        }
    }

    /// Whether this build includes a native keyring implementation.
    #[must_use]
    pub const fn is_available() -> bool {
        cfg!(all(
            feature = "os-keyring",
            any(
                target_os = "linux",
                target_os = "macos",
                target_os = "windows"
            )
        ))
    }
}

impl Default for OsKeyringBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for OsKeyringBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OsKeyringBackend")
            .field("available", &Self::is_available())
            .finish_non_exhaustive()
    }
}

impl SecretBackend for OsKeyringBackend {
    fn keyring(&self, service: &str, account: &str) -> Result<Option<SecretValue>, SecretError> {
        let Some(value) = self.provider.get(service, account)? else {
            return Ok(None);
        };
        if value.is_empty() {
            return Err(SecretError::EmptySecret);
        }
        Ok(Some(value))
    }
}

/// Alias kept for call sites that use the shorter backend name.
pub type KeyringBackend = OsKeyringBackend;

#[derive(Clone, Copy, Debug, Default)]
struct PlatformKeyring;

impl KeyringProvider for PlatformKeyring {
    #[cfg(all(
        feature = "os-keyring",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, SecretError> {
        let entry =
            keyring::Entry::new(service, account).map_err(|_| SecretError::KeyringUnavailable)?;
        match entry.get_secret() {
            Ok(bytes) => SecretValue::from_bytes(bytes)
                .map(Some)
                .map_err(SecretError::InvalidValue),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(SecretError::KeyringUnavailable),
        }
    }

    #[cfg(not(all(
        feature = "os-keyring",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    )))]
    fn get(&self, _service: &str, _account: &str) -> Result<Option<SecretValue>, SecretError> {
        Err(SecretError::KeyringUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{SecretRef, SecretSourceKind};

    #[derive(Clone, Default)]
    struct MockKeyring {
        calls: Arc<Mutex<Vec<(String, String)>>>,
        value: Option<SecretValue>,
    }

    impl MockKeyring {
        fn with_value(value: &str) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                value: Some(SecretValue::new(value)),
            }
        }
    }

    impl KeyringProvider for MockKeyring {
        fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, SecretError> {
            self.calls
                .lock()
                .expect("mock keyring lock")
                .push((service.to_owned(), account.to_owned()));
            Ok(self.value.clone())
        }
    }

    #[test]
    fn injected_keyring_provider_resolves_without_exposing_value() {
        let mock = MockKeyring::with_value("keyring-secret");
        let calls = Arc::clone(&mock.calls);
        let backend = OsKeyringBackend::with_provider(mock);
        let reference = SecretRef::parse("keyring:pooler/account").expect("reference");
        let value = reference
            .resolve_with(&crate::SecretResolveOptions::default(), &backend)
            .expect("secret");

        assert_eq!(value.expose_secret(), "keyring-secret");
        assert_eq!(reference.kind(), SecretSourceKind::Keyring);
        assert_eq!(
            calls.lock().expect("mock keyring lock").as_slice(),
            [("pooler".into(), "account".into())]
        );
        assert!(!format!("{backend:?}").contains("keyring-secret"));
    }

    #[test]
    fn empty_injected_value_fails_closed() {
        let backend = OsKeyringBackend::with_provider(MockKeyring::with_value(""));
        let reference = SecretRef::parse("keyring:pooler/account").expect("reference");
        assert!(matches!(
            reference.resolve_with(&crate::SecretResolveOptions::default(), &backend),
            Err(SecretError::EmptySecret)
        ));
    }

    #[test]
    fn default_backend_does_not_fall_back_when_unavailable() {
        if !OsKeyringBackend::is_available() {
            let reference = SecretRef::parse("keyring:pooler/account").expect("reference");
            assert!(matches!(
                reference.resolve(),
                Err(SecretError::KeyringUnavailable) | Err(SecretError::BackendUnavailable(_))
            ));
        }
    }
}
