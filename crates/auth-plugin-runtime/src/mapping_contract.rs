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
//! `mode = mapping`'s `mapping` guest entry point wire contract (ADR 0025 §4
//! "Guest Contract - `mapping` Mode") and the host-side response bounds it
//! must be validated against - the same shape of defense as
//! [`crate::auth_contract`]'s `authenticate` bounds (§7 "Response Payload
//! Bounds"), applied to a plugin that only ever produces claims, never an
//! `Allow` decision.
//!
//! The request side is identical to `full_auth` mode's, so
//! [`crate::auth_contract::AuthPluginRequest`] is reused verbatim (ADR §4:
//! `mapping(request: AuthPluginRequest) -> MappingResponse`).
use std::collections::HashMap;

use serde::Deserialize;
use thiserror::Error;

/// The Mapping Engine's `unique_workload_id` (ADR 0020 §3) has no dedicated
/// field on [`MappingResponse::Claims`] - the plugin author supplies it
/// under this reserved claim key instead, and it is left in the returned
/// claims map (unlike every other `__keystone`-prefixed key, which stays
/// forbidden) so mapping rules can also reference it directly.
pub const WORKLOAD_ID_CLAIM_KEY: &str = "__keystone_workload_id";

/// What a `mapping`-mode plugin's `mapping` entry point returns.
///
/// Wire shape is internally tagged on `"decision"`, mirroring
/// [`crate::auth_contract::AuthPluginResponse`]:
/// `{"decision":"claims","claims":{...}}` /
/// `{"decision":"deny","reason":"..."}`. There is no `Allow` variant - a
/// `mapping`-mode plugin cannot terminate authentication, only feed the Mapping
/// Engine that does (ADR §4).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum MappingResponse {
    Claims {
        claims: HashMap<String, serde_json::Value>,
    },
    Deny {
        reason: String,
    },
}

/// Response payload bounds (ADR §7), reused verbatim from the `full_auth`
/// decoder - a `mapping`-mode plugin is exactly as untrusted as a
/// `full_auth`-mode one.
pub const MAX_RESPONSE_BYTES: usize = crate::auth_contract::MAX_RESPONSE_BYTES;
pub const MAX_CLAIMS: usize = crate::auth_contract::MAX_CLAIMS;
pub const MAX_CLAIM_KEY_BYTES: usize = crate::auth_contract::MAX_CLAIM_KEY_BYTES;
pub const MAX_CLAIM_VALUE_BYTES: usize = crate::auth_contract::MAX_CLAIM_VALUE_BYTES;
pub const RESERVED_KEY_PREFIX: &str = crate::auth_contract::RESERVED_KEY_PREFIX;

/// Why a `mapping` response was rejected before ever being trusted.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MappingResponseBoundsError {
    #[error("mapping response of {0} bytes exceeds the {MAX_RESPONSE_BYTES}-byte cap")]
    ResponseTooLarge(usize),
    #[error("mapping response has {0} claims, exceeding the {MAX_CLAIMS}-claim cap")]
    TooManyClaims(usize),
    #[error("a claim key exceeded the {MAX_CLAIM_KEY_BYTES}-byte cap")]
    ClaimKeyTooLong,
    #[error("claim value for key exceeded the {MAX_CLAIM_VALUE_BYTES}-byte cap")]
    ClaimValueTooLong,
    #[error("a claim key used the reserved `{RESERVED_KEY_PREFIX}` prefix")]
    ReservedClaimKey,
    #[error("mapping response is missing the required `{WORKLOAD_ID_CLAIM_KEY}` string claim")]
    MissingWorkloadId,
    #[error("mapping response was malformed")]
    Malformed,
}

/// Decode and bounds-check a raw `mapping` response before any of its
/// content is trusted (same untrusted-input posture as
/// [`crate::auth_contract::decode_and_validate_response`]). On success,
/// [`WORKLOAD_ID_CLAIM_KEY`] is guaranteed present in `Claims` as a string.
pub fn decode_and_validate_mapping_response(
    raw: &[u8],
) -> Result<MappingResponse, MappingResponseBoundsError> {
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(MappingResponseBoundsError::ResponseTooLarge(raw.len()));
    }
    let response: MappingResponse =
        serde_json::from_slice(raw).map_err(|_| MappingResponseBoundsError::Malformed)?;

    if let MappingResponse::Claims { claims } = &response {
        if claims.len() > MAX_CLAIMS {
            return Err(MappingResponseBoundsError::TooManyClaims(claims.len()));
        }
        for (key, value) in claims {
            if key.len() > MAX_CLAIM_KEY_BYTES {
                return Err(MappingResponseBoundsError::ClaimKeyTooLong);
            }
            if key != WORKLOAD_ID_CLAIM_KEY && key.starts_with(RESERVED_KEY_PREFIX) {
                return Err(MappingResponseBoundsError::ReservedClaimKey);
            }
            let value_len = serde_json::to_vec(value)
                .map(|bytes| bytes.len())
                .unwrap_or(usize::MAX);
            if value_len > MAX_CLAIM_VALUE_BYTES {
                return Err(MappingResponseBoundsError::ClaimValueTooLong);
            }
        }
        match claims.get(WORKLOAD_ID_CLAIM_KEY) {
            Some(serde_json::Value::String(_)) => {}
            _ => return Err(MappingResponseBoundsError::MissingWorkloadId),
        }
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_json(mut claims: serde_json::Map<String, serde_json::Value>) -> Vec<u8> {
        claims
            .entry(WORKLOAD_ID_CLAIM_KEY.to_string())
            .or_insert_with(|| serde_json::json!("workload-1"));
        serde_json::to_vec(&serde_json::json!({
            "decision": "claims",
            "claims": claims,
        }))
        .unwrap()
    }

    #[test]
    fn test_decode_valid_claims() {
        let mut claims = serde_json::Map::new();
        claims.insert("risk".to_string(), serde_json::json!(3));
        let raw = claims_json(claims);
        match decode_and_validate_mapping_response(&raw).unwrap() {
            MappingResponse::Claims { claims } => {
                assert_eq!(claims.get("risk"), Some(&serde_json::json!(3)));
                assert_eq!(
                    claims.get(WORKLOAD_ID_CLAIM_KEY),
                    Some(&serde_json::json!("workload-1"))
                );
            }
            MappingResponse::Deny { .. } => panic!("expected Claims"),
        }
    }

    #[test]
    fn test_decode_valid_deny() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "decision": "deny",
            "reason": "nope",
        }))
        .unwrap();
        match decode_and_validate_mapping_response(&raw).unwrap() {
            MappingResponse::Deny { reason } => assert_eq!(reason, "nope"),
            MappingResponse::Claims { .. } => panic!("expected Deny"),
        }
    }

    #[test]
    fn test_rejects_missing_workload_id() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "decision": "claims",
            "claims": {"risk": 3},
        }))
        .unwrap();
        let err = decode_and_validate_mapping_response(&raw).unwrap_err();
        assert_eq!(err, MappingResponseBoundsError::MissingWorkloadId);
    }

    #[test]
    fn test_rejects_non_string_workload_id() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "decision": "claims",
            "claims": {WORKLOAD_ID_CLAIM_KEY: 123},
        }))
        .unwrap();
        let err = decode_and_validate_mapping_response(&raw).unwrap_err();
        assert_eq!(err, MappingResponseBoundsError::MissingWorkloadId);
    }

    #[test]
    fn test_rejects_oversized_response() {
        let huge = "x".repeat(MAX_RESPONSE_BYTES + 1);
        let err = decode_and_validate_mapping_response(huge.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            MappingResponseBoundsError::ResponseTooLarge(huge.len())
        );
    }

    #[test]
    fn test_rejects_too_many_claims() {
        // `claims_json` adds the workload-id claim on top, so filling to
        // `MAX_CLAIMS` here yields `MAX_CLAIMS + 1` total claims.
        let mut claims = serde_json::Map::new();
        for i in 0..MAX_CLAIMS {
            claims.insert(format!("k{i}"), serde_json::json!(1));
        }
        let raw = claims_json(claims);
        let err = decode_and_validate_mapping_response(&raw).unwrap_err();
        assert_eq!(
            err,
            MappingResponseBoundsError::TooManyClaims(MAX_CLAIMS + 1)
        );
    }

    #[test]
    fn test_rejects_oversized_claim_key() {
        let key = "k".repeat(MAX_CLAIM_KEY_BYTES + 1);
        let mut claims = serde_json::Map::new();
        claims.insert(key, serde_json::json!(1));
        let raw = claims_json(claims);
        let err = decode_and_validate_mapping_response(&raw).unwrap_err();
        assert_eq!(err, MappingResponseBoundsError::ClaimKeyTooLong);
    }

    #[test]
    fn test_rejects_oversized_claim_value() {
        let value = "v".repeat(MAX_CLAIM_VALUE_BYTES + 1);
        let mut claims = serde_json::Map::new();
        claims.insert("k".to_string(), serde_json::json!(value));
        let raw = claims_json(claims);
        let err = decode_and_validate_mapping_response(&raw).unwrap_err();
        assert_eq!(err, MappingResponseBoundsError::ClaimValueTooLong);
    }

    #[test]
    fn test_rejects_other_reserved_key_prefix() {
        let mut claims = serde_json::Map::new();
        claims.insert("__keystone_admin".to_string(), serde_json::json!(true));
        let raw = claims_json(claims);
        let err = decode_and_validate_mapping_response(&raw).unwrap_err();
        assert_eq!(err, MappingResponseBoundsError::ReservedClaimKey);
    }

    #[test]
    fn test_rejects_malformed_json() {
        let err = decode_and_validate_mapping_response(b"not json").unwrap_err();
        assert_eq!(err, MappingResponseBoundsError::Malformed);
    }
}
