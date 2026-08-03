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
//! `mode = full_auth`'s `authenticate` guest entry point wire contract (ADR
//! 0025 §4 "Guest Contract - `full_auth` Mode") and the host-side response
//! bounds it must be validated against (§7 "Response Payload Bounds").
//!
//! Kept in this crate (not `core`) because it's a pure wasm wire-boundary
//! concern - no `Service`/DB dependency - matching how
//! [`crate::ResolvedIdentityHandle`]/[`crate::ProvisionUserRequest`] are
//! already homed here rather than in `core`.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ResolvedIdentityHandle;

/// What a `full_auth`-mode plugin's `authenticate` entry point receives.
#[derive(Debug, Clone, Serialize)]
pub struct AuthPluginRequest {
    /// The raw `identity.<plugin_name>` JSON block from the client's
    /// `POST /v3/auth/tokens` request body.
    pub payload: serde_json::Value,
    /// `exposed_headers`-filtered inbound request headers, with
    /// [`HARD_DENYLISTED_HEADERS`] re-checked defensively by the caller.
    pub headers: HashMap<String, String>,
    /// Trusted client address, resolved via the plugin's configured
    /// trusted-proxy list - `None` if it couldn't be determined.
    pub remote_addr: Option<String>,
}

/// What a `full_auth`-mode plugin's `authenticate` entry point returns.
///
/// Wire shape is internally tagged on `"decision"`:
/// `{"decision":"allow","resolved_identity":"...","claims":{...}}` /
/// `{"decision":"deny","reason":"..."}` - a flat discriminant field is
/// straightforward for a plugin author in any language to produce, unlike a
/// Rust-`serde`-specific externally-tagged shape.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum AuthPluginResponse {
    Allow {
        resolved_identity: ResolvedIdentityHandle,
        #[serde(default)]
        claims: HashMap<String, serde_json::Value>,
    },
    Deny {
        reason: String,
    },
}

/// Response payload bounds (ADR §7): hard caps enforced host-side on every
/// `authenticate` response, regardless of what a plugin's own logic
/// produces - a compromised or buggy plugin cannot use an oversized or
/// malformed response to exhaust host memory or smuggle claims into a
/// reserved namespace.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_CLAIMS: usize = 64;
pub const MAX_CLAIM_KEY_BYTES: usize = 256;
pub const MAX_CLAIM_VALUE_BYTES: usize = 4 * 1024;
/// A plugin's own claims are always nested under
/// `plugin_claims.<plugin_name>.*` (see `Credentials.plugin_claims` in
/// `openstack-keystone-core`) - a claim key literally named `plugin_claims`
/// would be a same-level collision attempt with that host-constructed envelope
/// key.
pub const RESERVED_ENVELOPE_KEY: &str = "plugin_claims";
/// Reserved for host-internal use; a plugin claim key must never begin with
/// this prefix (ADR §7).
pub const RESERVED_KEY_PREFIX: &str = "__keystone";

/// Why an `authenticate` response was rejected before ever being trusted.
/// Every variant is constructed with just enough information to log and
/// audit - never the attacker/plugin-influenced content itself (ADR §7: "the
/// specific bound that was exceeded is recorded... without echoing
/// attacker-influenced content").
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResponseBoundsError {
    #[error("authenticate response of {0} bytes exceeds the {MAX_RESPONSE_BYTES}-byte cap")]
    ResponseTooLarge(usize),
    #[error("authenticate response has {0} claims, exceeding the {MAX_CLAIMS}-claim cap")]
    TooManyClaims(usize),
    #[error("a claim key exceeded the {MAX_CLAIM_KEY_BYTES}-byte cap")]
    ClaimKeyTooLong,
    #[error("claim value for key exceeded the {MAX_CLAIM_VALUE_BYTES}-byte cap")]
    ClaimValueTooLong,
    #[error(
        "a claim key used the reserved `{RESERVED_ENVELOPE_KEY}` name or `{RESERVED_KEY_PREFIX}` prefix"
    )]
    ReservedClaimKey,
    #[error("authenticate response was malformed")]
    Malformed,
}

/// Decode and bounds-check a raw `authenticate` response before any of its
/// content is trusted. Must be called on every response, regardless of how
/// small/well-formed it looks - a plugin is untrusted input (ADR §1 Threat
/// Model, actor 2: every invocation is triggered by an anonymous,
/// pre-authentication caller).
pub fn decode_and_validate_response(raw: &[u8]) -> Result<AuthPluginResponse, ResponseBoundsError> {
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(ResponseBoundsError::ResponseTooLarge(raw.len()));
    }
    let response: AuthPluginResponse =
        serde_json::from_slice(raw).map_err(|_| ResponseBoundsError::Malformed)?;

    if let AuthPluginResponse::Allow { claims, .. } = &response {
        if claims.len() > MAX_CLAIMS {
            return Err(ResponseBoundsError::TooManyClaims(claims.len()));
        }
        for (key, value) in claims {
            if key.len() > MAX_CLAIM_KEY_BYTES {
                return Err(ResponseBoundsError::ClaimKeyTooLong);
            }
            if key == RESERVED_ENVELOPE_KEY || key.starts_with(RESERVED_KEY_PREFIX) {
                return Err(ResponseBoundsError::ReservedClaimKey);
            }
            let value_len = serde_json::to_vec(value)
                .map(|bytes| bytes.len())
                .unwrap_or(usize::MAX);
            if value_len > MAX_CLAIM_VALUE_BYTES {
                return Err(ResponseBoundsError::ClaimValueTooLong);
            }
        }
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_json(claims: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "decision": "allow",
            "resolved_identity": "h",
            "claims": claims,
        }))
        .unwrap()
    }

    #[test]
    fn test_decode_valid_allow() {
        let raw = allow_json(serde_json::json!({"risk": 3}));
        let response = decode_and_validate_response(&raw).unwrap();
        match response {
            AuthPluginResponse::Allow {
                resolved_identity,
                claims,
            } => {
                assert_eq!(resolved_identity, ResolvedIdentityHandle("h".to_string()));
                assert_eq!(claims.get("risk"), Some(&serde_json::json!(3)));
            }
            AuthPluginResponse::Deny { .. } => panic!("expected Allow"),
        }
    }

    #[test]
    fn test_decode_valid_deny() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "decision": "deny",
            "reason": "nope",
        }))
        .unwrap();
        match decode_and_validate_response(&raw).unwrap() {
            AuthPluginResponse::Deny { reason } => assert_eq!(reason, "nope"),
            AuthPluginResponse::Allow { .. } => panic!("expected Deny"),
        }
    }

    #[test]
    fn test_rejects_oversized_response() {
        let huge = "x".repeat(MAX_RESPONSE_BYTES + 1);
        let err = decode_and_validate_response(huge.as_bytes()).unwrap_err();
        assert_eq!(err, ResponseBoundsError::ResponseTooLarge(huge.len()));
    }

    #[test]
    fn test_rejects_too_many_claims() {
        let mut claims = serde_json::Map::new();
        for i in 0..=MAX_CLAIMS {
            claims.insert(format!("k{i}"), serde_json::json!(1));
        }
        let raw = allow_json(serde_json::Value::Object(claims));
        let err = decode_and_validate_response(&raw).unwrap_err();
        assert_eq!(err, ResponseBoundsError::TooManyClaims(MAX_CLAIMS + 1));
    }

    #[test]
    fn test_rejects_oversized_claim_key() {
        let key = "k".repeat(MAX_CLAIM_KEY_BYTES + 1);
        let raw = allow_json(serde_json::json!({ key: 1 }));
        let err = decode_and_validate_response(&raw).unwrap_err();
        assert_eq!(err, ResponseBoundsError::ClaimKeyTooLong);
    }

    #[test]
    fn test_rejects_oversized_claim_value() {
        let value = "v".repeat(MAX_CLAIM_VALUE_BYTES + 1);
        let raw = allow_json(serde_json::json!({ "k": value }));
        let err = decode_and_validate_response(&raw).unwrap_err();
        assert_eq!(err, ResponseBoundsError::ClaimValueTooLong);
    }

    #[test]
    fn test_rejects_reserved_envelope_key() {
        let raw = allow_json(serde_json::json!({ "plugin_claims": {} }));
        let err = decode_and_validate_response(&raw).unwrap_err();
        assert_eq!(err, ResponseBoundsError::ReservedClaimKey);
    }

    #[test]
    fn test_rejects_reserved_key_prefix() {
        let raw = allow_json(serde_json::json!({ "__keystone_admin": true }));
        let err = decode_and_validate_response(&raw).unwrap_err();
        assert_eq!(err, ResponseBoundsError::ReservedClaimKey);
    }

    #[test]
    fn test_rejects_malformed_json() {
        let err = decode_and_validate_response(b"not json").unwrap_err();
        assert_eq!(err, ResponseBoundsError::Malformed);
    }
}
