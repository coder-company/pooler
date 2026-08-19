use std::fmt;

use http::header::{HeaderMap, AUTHORIZATION};
use thiserror::Error;
use zeroize::Zeroize;

/// A bearer credential extracted from an HTTP `Authorization` header.
///
/// The token intentionally has a redacted [`Debug`] implementation.  Callers
/// that need to send it onward can use [`BearerToken::as_str`] at the narrow
/// point where the header is constructed.
#[derive(Clone, Eq, PartialEq)]
pub struct BearerToken(String);

impl Drop for BearerToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl BearerToken {
    /// Construct a token after validating the token68 grammar.
    pub fn new(token: impl Into<String>) -> Result<Self, BearerError> {
        let token = token.into();
        if is_valid_token68(&token) {
            Ok(Self(token))
        } else {
            Err(BearerError::InvalidFormat)
        }
    }

    /// Borrow the credential for the shortest possible scope.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for BearerToken {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken(REDACTED)")
    }
}

/// Errors found while parsing a bearer credential.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum BearerError {
    /// An `Authorization` value contained bytes that are not valid header
    /// text.
    #[error("authorization header is not valid UTF-8")]
    InvalidUtf8,
    /// The bearer scheme was present but did not contain exactly one valid
    /// token68 credential.
    #[error("invalid bearer authorization format")]
    InvalidFormat,
    /// Multiple authorization values were supplied.  Treating one as the
    /// credential would make authentication ambiguous.
    #[error("multiple authorization headers are not accepted")]
    MultipleAuthorizationHeaders,
}

/// Extract a bearer credential, retaining parse errors for authentication
/// diagnostics.
///
/// A missing `Authorization` header, or an authorization scheme other than
/// `Bearer`, returns `Ok(None)`.  A malformed bearer value returns an error.
pub fn extract_bearer_token(headers: &HeaderMap) -> Result<Option<BearerToken>, BearerError> {
    let values = headers.get_all(AUTHORIZATION);
    let mut iter = values.iter();
    let Some(value) = iter.next() else {
        return Ok(None);
    };

    if iter.next().is_some() {
        return Err(BearerError::MultipleAuthorizationHeaders);
    }

    let text = value.to_str().map_err(|_| BearerError::InvalidUtf8)?;
    let mut parts = text.split_ascii_whitespace();
    let Some(scheme) = parts.next() else {
        return Err(BearerError::InvalidFormat);
    };

    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }

    let Some(token) = parts.next() else {
        return Err(BearerError::InvalidFormat);
    };
    if parts.next().is_some() || !is_valid_token68(token) {
        return Err(BearerError::InvalidFormat);
    }

    Ok(Some(BearerToken(token.to_owned())))
}

/// Extract a bearer credential while treating malformed or ambiguous input as
/// unauthenticated.
#[must_use]
pub fn extract_bearer(headers: &HeaderMap) -> Option<BearerToken> {
    extract_bearer_token(headers).ok().flatten()
}

/// Alias for callers that name credentials `secret` at an auth boundary.
pub fn extract_bearer_secret(headers: &HeaderMap) -> Option<BearerToken> {
    extract_bearer(headers)
}

fn is_valid_token68(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }

    let mut seen_value = false;
    let mut seen_padding = false;
    for character in token.bytes() {
        if character == b'=' {
            seen_padding = true;
            continue;
        }

        // RFC 9110 token68 permits alphanumeric characters and these four
        // punctuation characters.  Padding is only valid at the end.
        let valid = character.is_ascii_alphanumeric()
            || matches!(character, b'-' | b'.' | b'_' | b'~' | b'+' | b'/');
        if !valid || seen_padding {
            return false;
        }
        seen_value = true;
    }

    seen_value
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderValue, AUTHORIZATION};

    #[test]
    fn extracts_case_insensitive_bearer_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("bEaReR abc.DEF+/=="),
        );

        let token = extract_bearer_token(&headers).unwrap().unwrap();
        assert_eq!(token.as_str(), "abc.DEF+/==");
        assert_eq!(format!("{token:?}"), "BearerToken(REDACTED)");
    }

    #[test]
    fn rejects_malformed_bearer_and_duplicates() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer one two"));
        assert_eq!(
            extract_bearer_token(&headers),
            Err(BearerError::InvalidFormat)
        );

        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer two"));
        assert_eq!(
            extract_bearer_token(&headers),
            Err(BearerError::MultipleAuthorizationHeaders)
        );
    }

    #[test]
    fn ignores_other_auth_schemes() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(extract_bearer_token(&headers).unwrap(), None);
    }

    #[test]
    fn requires_a_value_before_padding() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer ==="));
        assert_eq!(
            extract_bearer_token(&headers),
            Err(BearerError::InvalidFormat)
        );
    }
}
