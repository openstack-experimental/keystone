// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # SCIM ETag helpers (ADR 0024 §5.E)
//!
//! `ScimResourceIndex.version` is the sole source of the SCIM weak ETag.
//! Handlers use [`etag_header`] to render it on responses and
//! [`parse_if_match`] to read a request's `If-Match` precondition before
//! passing it through as `expected_version` on the `update_index` call,
//! which performs the actual compare-and-swap.

use axum::http::HeaderMap;

use openstack_keystone_core::api::KeystoneApiError;

use crate::scim::error::ScimApiError;

/// Render a `ScimResourceIndex.version` as a weak ETag: `W/"<version>"`.
pub fn etag_header(version: u64) -> String {
    format!(r#"W/"{version}""#)
}

/// Parse an `If-Match` header value into the version it names.
///
/// Accepts `W/"<n>"`, `"<n>"`, or a bare `<n>`. Absent header returns
/// `Ok(None)` (no precondition to enforce); a present-but-unparsable value
/// is a client error, not a precondition mismatch.
pub fn parse_if_match(headers: &HeaderMap) -> Result<Option<u64>, ScimApiError> {
    let Some(value) = headers.get("if-match") else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| {
        KeystoneApiError::BadRequest("If-Match header is not valid UTF-8".to_string())
    })?;
    let trimmed = value.strip_prefix("W/").unwrap_or(value).trim();
    let trimmed = trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed);
    trimmed.parse::<u64>().map(Some).map_err(|_| {
        KeystoneApiError::BadRequest(format!("malformed If-Match header: `{value}`")).into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("if-match", value.parse().unwrap());
        headers
    }

    #[test]
    fn test_etag_header_format() {
        assert_eq!(etag_header(3), r#"W/"3""#);
    }

    #[test]
    fn test_parse_if_match_weak_form() {
        assert_eq!(parse_if_match(&headers_with(r#"W/"3""#)).unwrap(), Some(3));
    }

    #[test]
    fn test_parse_if_match_bare_quoted() {
        assert_eq!(parse_if_match(&headers_with(r#""5""#)).unwrap(), Some(5));
    }

    #[test]
    fn test_parse_if_match_bare_number() {
        assert_eq!(parse_if_match(&headers_with("7")).unwrap(), Some(7));
    }

    #[test]
    fn test_parse_if_match_absent() {
        assert_eq!(parse_if_match(&HeaderMap::new()).unwrap(), None);
    }

    #[test]
    fn test_parse_if_match_malformed() {
        let result = parse_if_match(&headers_with("not-a-number"));
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::BadRequest(_)))
        ));
    }
}
