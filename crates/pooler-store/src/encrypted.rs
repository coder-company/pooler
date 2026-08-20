//! Encrypted credential payloads.
//!
//! This module deliberately owns the cryptographic boundary for persisted
//! credential material.  Callers provide a resolved master-key source through
//! [`MasterKey`]; the store never serializes or logs that source or a payload.
//! The envelope is a small versioned binary format so unsupported data fails
//! closed instead of being guessed at.

use std::fmt;
use std::sync::Arc;

use pooler_auth::{OsKeyringBackend, SecretBackend, SecretRef, SecretResolveOptions, SecretValue};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::{StoreError, StoreResult};

const ENVELOPE_MAGIC: &[u8; 4] = b"PLCP";
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_ALGORITHM_AES_256_GCM: u8 = 1;
const KEY_ID_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const HEADER_LENGTH: usize = 4 + 1 + 1 + 1 + KEY_ID_LENGTH + NONCE_LENGTH;
const DERIVATION_SALT: &[u8] = b"pooler credential payload key v1";
const DERIVATION_INFO: &[u8] = b"pooler credential payload aes-256-gcm v1";

struct KeyLength;

impl KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

/// A master key retained by the encrypted store.
///
/// The key is derived through HKDF-SHA256 from externally resolved secret
/// material.  The source reference itself is never retained, serialized, or
/// included in an error.  A short digest-derived identifier is stored in each
/// envelope solely to reject a payload opened with the wrong key.
#[derive(Clone)]
pub struct MasterKey {
    key: Arc<Zeroizing<[u8; 32]>>,
    id: [u8; KEY_ID_LENGTH],
}

impl MasterKey {
    /// Resolve a master key from an authentication [`SecretRef`].
    ///
    /// Literal references are rejected even when a caller has enabled literal
    /// secrets for another purpose.  A production persistence key must cross
    /// an external secret boundary.
    pub fn from_secret_ref(reference: &SecretRef) -> StoreResult<Self> {
        Self::from_secret_ref_with(
            reference,
            &SecretResolveOptions::default(),
            &OsKeyringBackend::default(),
        )
    }

    /// Resolve a master key with an explicit external secret backend.
    pub fn from_secret_ref_with(
        reference: &SecretRef,
        options: &SecretResolveOptions,
        backend: &dyn SecretBackend,
    ) -> StoreResult<Self> {
        if matches!(reference, SecretRef::Literal(_)) {
            return Err(StoreError::MasterKeyReferenceRejected);
        }
        let value = reference
            .resolve_with(options, backend)
            .map_err(|_| StoreError::MasterKeyUnavailable)?;
        Self::from_secret_value(&value)
    }

    /// Derive a key from a protected secret value.
    pub fn from_secret_value(value: &SecretValue) -> StoreResult<Self> {
        Self::from_bytes(value.expose_bytes())
    }

    /// Derive a key from externally owned bytes.
    ///
    /// This is useful for a process-integrated keyring adapter and tests.  The
    /// bytes are copied only into the zeroizing key representation; callers
    /// remain responsible for the lifetime of their input buffer.
    pub fn from_bytes(value: &[u8]) -> StoreResult<Self> {
        if value.is_empty() {
            return Err(StoreError::EmptyMasterKey);
        }

        let salt = Salt::new(HKDF_SHA256, DERIVATION_SALT);
        let pseudo_random_key = salt.extract(value);
        let expanded = pseudo_random_key
            .expand(&[DERIVATION_INFO], KeyLength)
            .map_err(|_| StoreError::MasterKeyUnavailable)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        expanded
            .fill(&mut key[..])
            .map_err(|_| StoreError::MasterKeyUnavailable)?;

        let digest = digest(&SHA256, &key[..]);
        let mut id = [0_u8; KEY_ID_LENGTH];
        id.copy_from_slice(&digest.as_ref()[..KEY_ID_LENGTH]);
        Ok(Self {
            key: Arc::new(key),
            id,
        })
    }

    /// Return the non-secret envelope key identifier.
    #[must_use]
    pub const fn key_id(&self) -> [u8; KEY_ID_LENGTH] {
        self.id
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey([REDACTED])")
    }
}

/// A credential payload held in a zeroizing buffer.
///
/// This type intentionally does not implement `Serialize` or `Deserialize`.
/// Payloads cross the persistence boundary only through the authenticated
/// encrypted envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialPayload(Zeroizing<Vec<u8>>);

impl CredentialPayload {
    /// Construct a non-empty payload from owned bytes.
    pub fn from_bytes(value: Vec<u8>) -> StoreResult<Self> {
        if value.is_empty() {
            return Err(StoreError::EmptyCredentialPayload);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Construct a non-empty payload from a borrowed byte slice.
    pub fn new(value: &[u8]) -> StoreResult<Self> {
        Self::from_bytes(value.to_vec())
    }

    /// Borrow the payload only at the explicit provider boundary.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Alias for callers that use byte-container terminology.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.expose_bytes()
    }

    /// Return the payload length without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the wrapper at the explicit outbound boundary.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for CredentialPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialPayload([REDACTED])")
    }
}

impl fmt::Display for CredentialPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Backwards-compatible name for code that treats persisted credentials as
/// generic secret payloads.
pub type SecretPayload = CredentialPayload;

/// Internal immutable cipher selected by the current store key.
#[derive(Clone)]
pub(crate) struct CredentialCipher {
    key: MasterKey,
    random: Arc<SystemRandom>,
}

impl CredentialCipher {
    pub(crate) fn new(key: MasterKey) -> Self {
        Self {
            key,
            random: Arc::new(SystemRandom::new()),
        }
    }

    pub(crate) fn key_id(&self) -> [u8; KEY_ID_LENGTH] {
        self.key.key_id()
    }

    pub(crate) fn seal_for(
        &self,
        payload: &CredentialPayload,
        associated_data: &[u8],
    ) -> StoreResult<Vec<u8>> {
        let mut nonce = [0_u8; NONCE_LENGTH];
        self.random
            .fill(&mut nonce)
            .map_err(|_| StoreError::EncryptionFailed)?;

        let mut header = Vec::with_capacity(HEADER_LENGTH);
        header.extend_from_slice(ENVELOPE_MAGIC);
        header.push(ENVELOPE_VERSION);
        header.push(ENVELOPE_ALGORITHM_AES_256_GCM);
        header.push(KEY_ID_LENGTH as u8);
        header.extend_from_slice(&self.key_id());
        header.extend_from_slice(&nonce);
        let aad = authenticated_data(&header, associated_data);

        let mut ciphertext = payload.expose_bytes().to_vec();
        let key = self.aead_key()?;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad.as_slice()),
            &mut ciphertext,
        )
        .map_err(|_| StoreError::EncryptionFailed)?;

        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    pub(crate) fn open_for(
        &self,
        envelope: &[u8],
        associated_data: &[u8],
    ) -> StoreResult<CredentialPayload> {
        if envelope.len() < HEADER_LENGTH + TAG_LENGTH {
            return Err(StoreError::InvalidCredentialEnvelope);
        }
        let header = &envelope[..HEADER_LENGTH];
        if &header[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC {
            return Err(StoreError::InvalidCredentialEnvelope);
        }
        if header[4] != ENVELOPE_VERSION {
            return Err(StoreError::UnsupportedCredentialEnvelopeVersion(header[4]));
        }
        if header[5] != ENVELOPE_ALGORITHM_AES_256_GCM || header[6] as usize != KEY_ID_LENGTH {
            return Err(StoreError::UnsupportedCredentialEnvelopeAlgorithm);
        }
        let key_start = 7;
        let key_end = key_start + KEY_ID_LENGTH;
        if header[key_start..key_end] != self.key_id() {
            return Err(StoreError::WrongMasterKey);
        }

        let mut nonce = [0_u8; NONCE_LENGTH];
        nonce.copy_from_slice(&header[key_end..HEADER_LENGTH]);
        let aad = authenticated_data(header, associated_data);
        let mut plaintext = Zeroizing::new(envelope[HEADER_LENGTH..].to_vec());
        let key = self.aead_key()?;
        let plaintext_length = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut plaintext,
            )
            .map_err(|_| StoreError::CredentialEnvelopeAuthenticationFailed)?
            .len();
        plaintext.truncate(plaintext_length);
        CredentialPayload::from_bytes(plaintext.to_vec())
    }

    fn aead_key(&self) -> StoreResult<LessSafeKey> {
        let unbound = UnboundKey::new(&AES_256_GCM, self.key.key.as_ref().as_ref())
            .map_err(|_| StoreError::EncryptionFailed)?;
        Ok(LessSafeKey::new(unbound))
    }
}

fn authenticated_data(header: &[u8], associated_data: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + associated_data.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(associated_data);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockKeyring;

    impl SecretBackend for MockKeyring {
        fn keyring(
            &self,
            service: &str,
            account: &str,
        ) -> Result<Option<SecretValue>, pooler_auth::SecretError> {
            if service == "pooler" && account == "master" {
                return Ok(Some(SecretValue::new("master secret")));
            }
            Ok(None)
        }
    }

    #[test]
    fn key_derivation_is_stable_but_debug_is_redacted() {
        let first = MasterKey::from_bytes(b"master secret").expect("key");
        let second = MasterKey::from_bytes(b"master secret").expect("key");
        assert_eq!(first.key_id(), second.key_id());
        assert_eq!(format!("{first:?}"), "MasterKey([REDACTED])");
    }

    #[test]
    fn master_key_resolves_keyring_reference_through_injected_backend() {
        let reference = SecretRef::parse("keyring:pooler/master").expect("reference");
        let key = MasterKey::from_secret_ref_with(
            &reference,
            &SecretResolveOptions::default(),
            &MockKeyring,
        )
        .expect("master key");
        assert_eq!(
            key.key_id(),
            MasterKey::from_bytes(b"master secret")
                .expect("master key")
                .key_id()
        );
        assert_eq!(format!("{key:?}"), "MasterKey([REDACTED])");
    }

    #[test]
    fn envelope_round_trip_and_wrong_key_fail_closed() {
        let key = MasterKey::from_bytes(b"master secret").expect("key");
        let wrong = MasterKey::from_bytes(b"another secret").expect("key");
        let cipher = CredentialCipher::new(key);
        let payload = CredentialPayload::new(b"access-token").expect("payload");
        let envelope = cipher.seal_for(&payload, &[]).expect("seal");
        assert!(!envelope
            .windows(b"access-token".len())
            .any(|window| window == b"access-token"));
        assert_eq!(cipher.open_for(&envelope, &[]).expect("open"), payload);
        assert_eq!(
            CredentialCipher::new(wrong).open_for(&envelope, &[]),
            Err(StoreError::WrongMasterKey)
        );
    }

    #[test]
    fn envelope_tampering_is_rejected() {
        let key = MasterKey::from_bytes(b"master secret").expect("key");
        let cipher = CredentialCipher::new(key);
        let payload = CredentialPayload::new(b"access-token").expect("payload");
        let mut envelope = cipher.seal_for(&payload, &[]).expect("seal");
        let index = envelope.len() - 1;
        envelope[index] ^= 1;
        assert_eq!(
            cipher.open_for(&envelope, &[]),
            Err(StoreError::CredentialEnvelopeAuthenticationFailed)
        );
    }

    #[test]
    fn envelope_is_bound_to_its_associated_credential() {
        let key = MasterKey::from_bytes(b"master secret").expect("key");
        let cipher = CredentialCipher::new(key);
        let payload = CredentialPayload::new(b"access-token").expect("payload");
        let envelope = cipher.seal_for(&payload, b"credential-a").expect("seal");
        assert_eq!(
            cipher.open_for(&envelope, b"credential-b"),
            Err(StoreError::CredentialEnvelopeAuthenticationFailed)
        );
        assert_eq!(
            cipher.open_for(&envelope, b"credential-a").expect("open"),
            payload
        );
    }

    #[test]
    fn unsupported_versions_are_rejected() {
        let key = MasterKey::from_bytes(b"master secret").expect("key");
        let cipher = CredentialCipher::new(key);
        let payload = CredentialPayload::new(b"access-token").expect("payload");
        let mut envelope = cipher.seal_for(&payload, &[]).expect("seal");
        envelope[4] = ENVELOPE_VERSION + 1;
        assert_eq!(
            cipher.open_for(&envelope, &[]),
            Err(StoreError::UnsupportedCredentialEnvelopeVersion(
                ENVELOPE_VERSION + 1
            ))
        );
    }
}
