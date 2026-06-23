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
//! Shared helpers for federation claim flattening.

use std::collections::HashMap;

use serde_json::Value;

use openstack_keystone_core_types::mapping::error::MappingProviderError;

/// Maximum bytes allowed per individual claim value.
const CLAIM_VALUE_LIMIT: usize = 4096;

/// Maximum total serialized bytes for the flattened claims map.
const CLAIMS_MAP_LIMIT: usize = 64 * 1024;

/// Flatten a JSON claims object into the dotted-key claims map.
///
/// Walks the JSON value recursively, accumulating dotted key paths
/// (e.g., `user.profile.id`). Normalizes `String`, `Number`, and `Bool`
/// values to their string representation. Nested objects are traversed;
/// arrays are dropped (claim condition evaluation expects scalar values).
///
/// Enforces per-claim (4096 bytes) and total map (64 KiB) size caps per
/// ADR-0020 §9. Excess per-claim values are silently dropped; total map
/// exceeding 64 KiB returns an error.
///
/// # Arguments
/// * `claims_json` - The JSON-serialized claims object.
///
/// # Returns
/// Flattened claims map, or `MappingProviderError::ClaimsMapTooLarge` if
/// the total map exceeds 64 KiB.
pub(super) fn flatten_federation_claims(
    claims_json: &Value,
) -> Result<HashMap<String, Vec<String>>, MappingProviderError> {
    let mut claims = HashMap::new();
    flatten_value(claims_json, None, &mut claims)?;

    let total_bytes: usize = claims
        .iter()
        .map(|(k, v)| k.len() + v.iter().map(|s| s.len()).sum::<usize>())
        .sum();
    if total_bytes > CLAIMS_MAP_LIMIT {
        return Err(MappingProviderError::ClaimsMapTooLarge);
    }

    Ok(claims)
}

/// Recursively flatten a JSON value into the claims map.
///
/// # Arguments
/// * `value` - JSON value to process.
/// * `prefix` - Current dotted key path (e.g., `Some("user.profile")`).
/// * `claims` - The accumulator map.
fn flatten_value(
    value: &Value,
    prefix: Option<&str>,
    claims: &mut HashMap<String, Vec<String>>,
) -> Result<(), MappingProviderError> {
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let next = match prefix {
                    Some(p) => Some(format!("{p}.{key}")),
                    None => Some(key.clone()),
                };
                flatten_value(val, next.as_deref(), claims)?;
            }
        }
        Value::String(s) => {
            let key = prefix.unwrap_or("*").to_string();
            // Silently drop oversized values per ADR-0020 §9
            if s.len() <= CLAIM_VALUE_LIMIT {
                claims.entry(key).or_default().push(s.clone());
            }
        }
        Value::Number(n) => {
            let key = prefix.unwrap_or("*").to_string();
            let s = n.to_string();
            if s.len() <= CLAIM_VALUE_LIMIT {
                claims.entry(key).or_default().push(s);
            }
        }
        Value::Bool(b) => {
            let key = prefix.unwrap_or("*").to_string();
            claims.entry(key).or_default().push(b.to_string());
        }
        Value::Null | Value::Array(_) => {}
    }
    Ok(())
}
