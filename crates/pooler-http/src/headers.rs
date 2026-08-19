use std::collections::HashSet;

use http::header::{HeaderMap, HeaderName};

/// Headers that are specific to one HTTP connection and must not be forwarded
/// by a proxy.  `Proxy-Connection` is included as a legacy spelling accepted
/// by a number of clients; it is not a standard end-to-end header either.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove hop-by-hop headers from a map in place.
///
/// In addition to the standard fixed list, every field named by a
/// `Connection` header is removed.  Connection options are parsed
/// case-insensitively and malformed option names are ignored rather than
/// allowing them to affect unrelated fields.
pub fn strip_hop_by_hop_headers(headers: &mut HeaderMap) -> usize {
    let mut names = HashSet::with_capacity(HOP_BY_HOP_HEADERS.len());

    for name in HOP_BY_HOP_HEADERS {
        // `HeaderName::from_static` is available for all values in the fixed
        // list and avoids parsing on every request.
        names.insert(HeaderName::from_static(name));
    }

    // Collect before mutating the map so repeated Connection values and
    // arbitrary extension fields are handled without aliasing the iterator.
    for value in headers.get_all("connection").iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for option in value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if let Ok(name) = HeaderName::from_bytes(option.as_bytes()) {
                names.insert(name);
            }
        }
    }

    names
        .into_iter()
        .filter(|name| headers.remove(name).is_some())
        .count()
}

/// Alias emphasizing that this operation is suitable for either request or
/// response headers.
pub fn remove_hop_by_hop_headers(headers: &mut HeaderMap) -> usize {
    strip_hop_by_hop_headers(headers)
}

/// Short alias used by forwarding code.
pub fn sanitize_headers(headers: &mut HeaderMap) -> usize {
    strip_hop_by_hop_headers(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderValue, CONNECTION};

    #[test]
    fn removes_fixed_and_connection_declared_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("X-Trace, upgrade"));
        headers.insert("x-trace", HeaderValue::from_static("private"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        assert_eq!(strip_hop_by_hop_headers(&mut headers), 3);
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("x-trace"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(headers.contains_key("content-type"));
    }

    #[test]
    fn handles_multiple_connection_values_and_invalid_values() {
        let mut headers = HeaderMap::new();
        headers.append(CONNECTION, HeaderValue::from_static("x-one"));
        headers.append(CONNECTION, HeaderValue::from_static("X-TWO, TE"));
        headers.insert("x-one", HeaderValue::from_static("1"));
        headers.insert("x-two", HeaderValue::from_static("2"));
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));

        assert_eq!(remove_hop_by_hop_headers(&mut headers), 4);
        assert!(headers.is_empty());
    }
}
