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
//! `mode = route`'s `route` guest entry point wire contract (ADR 0025 §4
//! "Guest Contract - `route` Mode") and the host-side response bounds it
//! must be validated against - the same shape of defense as
//! [`crate::auth_contract`]'s `authenticate` bounds (§7 "Response Payload
//! Bounds"), applied to a plugin that only ever relabels which
//! already-registered method handles a request, never resolves an identity.
//!
//! Unlike `full_auth`/`mapping`, the request side is its own shape (not
//! [`crate::auth_contract::AuthPluginRequest`]) since a `route`-mode plugin
//! runs pre-dispatch on the raw, un-parsed `identity.methods` list rather
//! than a single method's already-isolated payload (ADR §4:
//! `route(request: RouteRequest) -> RouteResponse`).
//!
//! This decoder only enforces shape-level bounds (size, non-empty target).
//! It deliberately does not know the plugin's configured `route_targets`
//! allowlist - that's `core`/config state, unavailable in this crate - so
//! the allowlist check happens in `core`, same division of responsibility as
//! [`crate::mapping_contract`] not knowing about domains.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What a `route`-mode plugin's `route` entry point is invoked with: the
/// client's full, pre-dispatch `identity.methods` list, and the raw JSON
/// payload for each method block the plugin's config declared it needs to
/// inspect (`inspect_methods`) - never the full request, so a router never
/// sees the payload of a method it wasn't configured to look at.
#[derive(Debug, Clone, Serialize)]
pub struct RouteRequest {
    pub methods: Vec<String>,
    pub headers: HashMap<String, String>,
    pub payloads: HashMap<String, serde_json::Value>,
    pub remote_addr: Option<String>,
}

/// What a `route`-mode plugin's `route` entry point returns.
///
/// Wire shape is internally tagged on `"decision"`, mirroring
/// [`crate::auth_contract::AuthPluginResponse`]/
/// [`crate::mapping_contract::MappingResponse`]. There is no `Allow`/`Claims`
/// variant - a `route`-mode plugin has no authority to resolve or assert an
/// identity at all (ADR §4).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum RouteResponse {
    /// Leave the request exactly as received; ordinary method resolution
    /// proceeds as if no router plugin were installed.
    Passthrough,
    /// Reroute to `target_method`, replacing the `identity.<target_method>`
    /// block with `payload` verbatim. Whether `target_method` is actually a
    /// member of this plugin's configured `route_targets` allowlist is
    /// checked host-side in `core`, not by this decoder.
    Route {
        target_method: String,
        payload: serde_json::Value,
    },
    Deny {
        reason: String,
    },
}

/// Response payload bounds (ADR §7), reused verbatim from the `full_auth`
/// decoder - a `route`-mode plugin is exactly as untrusted as a
/// `full_auth`/`mapping`-mode one.
pub const MAX_RESPONSE_BYTES: usize = crate::auth_contract::MAX_RESPONSE_BYTES;
/// Reused as the `Route` payload's own size cap - a router's rewritten
/// payload is bounded the same as any single claim value.
pub const MAX_PAYLOAD_BYTES: usize = crate::auth_contract::MAX_CLAIM_VALUE_BYTES;

/// Why a `route` response was rejected before ever being trusted.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteResponseBoundsError {
    #[error("route response of {0} bytes exceeds the {MAX_RESPONSE_BYTES}-byte cap")]
    ResponseTooLarge(usize),
    #[error("route response payload exceeded the {MAX_PAYLOAD_BYTES}-byte cap")]
    PayloadTooLarge,
    #[error("route response named an empty target_method")]
    EmptyTargetMethod,
    #[error("route response was malformed")]
    Malformed,
}

/// Decode and bounds-check a raw `route` response before any of its content
/// is trusted (same untrusted-input posture as
/// [`crate::auth_contract::decode_and_validate_response`]).
pub fn decode_and_validate_route_response(
    raw: &[u8],
) -> Result<RouteResponse, RouteResponseBoundsError> {
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(RouteResponseBoundsError::ResponseTooLarge(raw.len()));
    }
    let response: RouteResponse =
        serde_json::from_slice(raw).map_err(|_| RouteResponseBoundsError::Malformed)?;

    if let RouteResponse::Route {
        target_method,
        payload,
    } = &response
    {
        if target_method.is_empty() {
            return Err(RouteResponseBoundsError::EmptyTargetMethod);
        }
        let payload_len = serde_json::to_vec(payload)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(RouteResponseBoundsError::PayloadTooLarge);
        }
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_valid_passthrough() {
        let raw = serde_json::to_vec(&serde_json::json!({"decision": "passthrough"})).unwrap();
        match decode_and_validate_route_response(&raw).unwrap() {
            RouteResponse::Passthrough => {}
            other => panic!("expected Passthrough, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_valid_route() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "decision": "route",
            "target_method": "tf_appcred_handler",
            "payload": {"application_credential_id": "abc"},
        }))
        .unwrap();
        match decode_and_validate_route_response(&raw).unwrap() {
            RouteResponse::Route {
                target_method,
                payload,
            } => {
                assert_eq!(target_method, "tf_appcred_handler");
                assert_eq!(payload["application_credential_id"], "abc");
            }
            other => panic!("expected Route, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_valid_deny() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "decision": "deny",
            "reason": "nope",
        }))
        .unwrap();
        match decode_and_validate_route_response(&raw).unwrap() {
            RouteResponse::Deny { reason } => assert_eq!(reason, "nope"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn test_rejects_empty_target_method() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "decision": "route",
            "target_method": "",
            "payload": {},
        }))
        .unwrap();
        let err = decode_and_validate_route_response(&raw).unwrap_err();
        assert_eq!(err, RouteResponseBoundsError::EmptyTargetMethod);
    }

    #[test]
    fn test_rejects_oversized_response() {
        let huge = "x".repeat(MAX_RESPONSE_BYTES + 1);
        let err = decode_and_validate_route_response(huge.as_bytes()).unwrap_err();
        assert_eq!(err, RouteResponseBoundsError::ResponseTooLarge(huge.len()));
    }

    #[test]
    fn test_rejects_oversized_payload() {
        let value = "v".repeat(MAX_PAYLOAD_BYTES + 1);
        let raw = serde_json::to_vec(&serde_json::json!({
            "decision": "route",
            "target_method": "tf_appcred_handler",
            "payload": {"blob": value},
        }))
        .unwrap();
        let err = decode_and_validate_route_response(&raw).unwrap_err();
        assert_eq!(err, RouteResponseBoundsError::PayloadTooLarge);
    }

    #[test]
    fn test_rejects_malformed_json() {
        let err = decode_and_validate_route_response(b"not json").unwrap_err();
        assert_eq!(err, RouteResponseBoundsError::Malformed);
    }
}
