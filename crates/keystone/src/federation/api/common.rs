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
//! Shared helpers for federation claim flattening and token issuance.

use std::collections::HashMap;

use serde_json::Value;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::mapping::error::MappingProviderError;
use openstack_keystone_core_types::scope::Scope;

use crate::api::error::KeystoneApiError;
use crate::api::types::{Catalog, CatalogService};
use crate::api::v4::auth::token::types::TokenResponse as KeystoneTokenResponse;
use crate::auth::SecurityContext;
use crate::keystone::ServiceState;

/// Maximum bytes allowed per individual claim value.
const CLAIM_VALUE_LIMIT: usize = 4096;

/// Maximum total serialized bytes for the flattened claims map.
const CLAIMS_MAP_LIMIT: usize = 64 * 1024;

/// Flatten a JSON claims object into a dotted-key claims map.
///
/// Walks the JSON value recursively, accumulating dotted key paths
/// (e.g., `user.profile.id`). Normalizes `String`, `Number`, and `Bool`
/// values to their string representation. Nested objects are traversed.
/// Arrays of scalars (string, number, bool, null) are collected into a
/// `Vec<String>` under the current key. Arrays containing nested objects
/// are flattened with indexed keys (e.g. `user.roles.0`, `user.roles.1`).
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

/// Check if all items in the array are scalar types (no nested objects/arrays).
fn is_scalar(item: &Value) -> bool {
    matches!(
        item,
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null
    )
}

/// Convert a scalar JSON value to its string representation.
fn scalar_as_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => unreachable!(),
    }
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
    let key = prefix.unwrap_or("*").to_string();

    match value {
        Value::Object(map) => {
            for (sub_key, sub_val) in map {
                let next_key = if prefix.is_some() {
                    format!("{key}.{sub_key}")
                } else {
                    sub_key.to_string()
                };
                flatten_value(sub_val, Some(&next_key), claims)?;
            }
        }
        Value::Array(arr) => {
            if arr.iter().all(is_scalar) {
                // Flat scalar array: collect directly into claims[key].
                for item in arr {
                    let s = scalar_as_string(item);
                    // Silently drop oversized values per ADR-0020 §9
                    if s.len() <= CLAIM_VALUE_LIMIT {
                        claims.entry(key.clone()).or_default().push(s);
                    }
                }
            } else {
                // Array of nested objects: flatten with indexed keys.
                for (i, item) in arr.iter().enumerate() {
                    let next_key = format!("{key}.{i}");
                    flatten_value(item, Some(&next_key), claims)?;
                }
            }
        }
        Value::String(s) => {
            // Silently drop oversized values per ADR-0020 §9
            if s.len() <= CLAIM_VALUE_LIMIT {
                claims.entry(key).or_default().push(s.clone());
            }
        }
        Value::Number(n) => {
            let s = n.to_string();
            if s.len() <= CLAIM_VALUE_LIMIT {
                claims.entry(key).or_default().push(s);
            }
        }
        Value::Bool(b) => {
            claims.entry(key).or_default().push(b.to_string());
        }
        Value::Null => {}
    }
    Ok(())
}

/// Build the Keystone token response from the mapping engine auth result.
///
/// Common boilerplate shared between OIDC callback and JWT login handlers:
/// resolves scope authorization, issues the token, attaches the service
/// catalog, and encodes the token.
///
/// # Arguments
/// * `state` - The service state.
/// * `auth_result` - AuthenticationResult from `authenticate_by_mapping`.
/// * `scope` - Scope requested during OIDC auth init (None for JWT flow).
///
/// # Returns
/// Tuple of (token_string, api_token_response_body).
/// The caller is responsible for attaching the response body to the HTTP
/// response and including the token string in the `x-subject-token` header.
pub(super) async fn build_token_response(
    state: &ServiceState,
    auth_result: &openstack_keystone_core_types::auth::AuthenticationResult,
    scope: Option<&Scope>,
) -> Result<(String, KeystoneTokenResponse), KeystoneApiError> {
    use openstack_keystone_api_types::v3::auth::token::TokenBuilder;
    use openstack_keystone_core::api::common::get_authz_info;

    let authz_info = get_authz_info(state, scope).await?;
    tracing::trace!("Granting the scope: {:?}", authz_info);

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            state,
            &SecurityContext::try_from(auth_result.clone())?,
            &authz_info,
        )
        .await?;

    let token_string = state
        .provider
        .get_token_provider()
        .encode_token(vsc.token()?)?;

    let mut api_token = KeystoneTokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };
    let catalog = Catalog(
        state
            .provider
            .get_catalog_provider()
            .get_catalog(&ExecutionContext::internal(state), true)
            .await?
            .into_iter()
            .map(|(s, es)| CatalogService {
                id: s.id.clone(),
                name: s.name(),
                r#type: s.r#type,
                endpoints: es.into_iter().map(Into::into).collect(),
            })
            .collect::<Vec<_>>(),
    );
    api_token.token.catalog = Some(catalog);

    Ok((token_string, api_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_string_claim() {
        let json = serde_json::json!({"name": "Alice"});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("name").unwrap(), vec!["Alice"]);
    }

    #[test]
    fn flatten_bool_claim() {
        let json = serde_json::json!({"active": true, "disabled": false});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("active").unwrap(), vec!["true"]);
        assert_eq!(*claims.get("disabled").unwrap(), vec!["false"]);
    }

    #[test]
    fn flatten_number_claim() {
        let json = serde_json::json!({"age": 42, "score": 3.14});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("age").unwrap(), vec!["42"]);
        assert_eq!(*claims.get("score").unwrap(), vec!["3.14"]);
    }

    #[test]
    fn flatten_null_is_dropped() {
        let json = serde_json::json!({"name": "A", "nothing": null});
        let claims = flatten_federation_claims(&json).unwrap();
        assert!(!claims.contains_key("nothing"));
    }

    #[test]
    fn flatten_nested_object() {
        let json = serde_json::json!({"user": {"profile": {"name": "Alice"}}});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("user.profile.name").unwrap(), vec!["Alice"]);
    }

    #[test]
    fn flatten_scalar_array() {
        let json = serde_json::json!({"groups": ["admin", "users", "readers"]});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(
            *claims.get("groups").unwrap(),
            vec!["admin", "users", "readers"]
        );
    }

    #[test]
    fn flatten_mixed_scalar_array() {
        let json = serde_json::json!({"values": ["text", 42, true, null]});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(
            *claims.get("values").unwrap(),
            vec!["text", "42", "true", ""]
        );
    }

    #[test]
    fn flatten_array_of_objects() {
        let json = serde_json::json!({ "roles": [{"id": "r1", "name": "admin"}, {"id": "r2", "name": "editor"}] });
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("roles.0.id").unwrap(), vec!["r1"]);
        assert_eq!(*claims.get("roles.0.name").unwrap(), vec!["admin"]);
        assert_eq!(*claims.get("roles.1.id").unwrap(), vec!["r2"]);
        assert_eq!(*claims.get("roles.1.name").unwrap(), vec!["editor"]);
    }

    #[test]
    fn flatten_deeply_nested() {
        let json = serde_json::json!({"a": {"b": {"c": {"d": "deep"}}}});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("a.b.c.d").unwrap(), vec!["deep"]);
    }

    #[test]
    fn flatten_empty_object() {
        let json = serde_json::json!({});
        let claims = flatten_federation_claims(&json).unwrap();
        assert!(claims.is_empty());
    }

    #[test]
    fn flatten_overlarge_value_dropped() {
        let large = "x".repeat(CLAIM_VALUE_LIMIT + 1);
        let json = serde_json::json!({"ok": "short", "huge": large});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("ok").unwrap(), vec!["short"]);
        assert!(
            !claims.contains_key("huge"),
            "oversized value must be dropped"
        );
    }

    #[test]
    fn flatten_overlarge_map_returns_error() {
        let vals: Vec<String> = (0..1000).map(|i| format!("key{i}").repeat(70)).collect();
        let mut map = serde_json::Map::new();
        for v in vals {
            map.insert(v.clone(), serde_json::Value::String(("v".to_string() + &v)));
        }
        let claims = flatten_federation_claims(&Value::Object(map));
        assert!(
            matches!(claims, Err(MappingProviderError::ClaimsMapTooLarge)),
            "over 64 KiB map must return error"
        );
    }

    #[test]
    fn flatten_oversized_array_item_dropped() {
        let large = "x".repeat(CLAIM_VALUE_LIMIT + 1);
        let json = serde_json::json!({"groups": ["admin", large]});
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("groups").unwrap(), vec!["admin"]);
    }

    #[test]
    fn flatten_empty_key_default() {
        // Top-level value with no prefix should use "*" key.
        let claims = flatten_federation_claims(&serde_json::json!("orphan"));
        assert!(claims.is_ok() && claims.unwrap().get("*").is_some());
    }

    #[test]
    fn flatten_complex_oidc_like_claims() {
        let json = serde_json::json!({
            "sub": "user123",
            "iss": "https://idp.example.com",
            "aud": ["my-client", "other-client"],
            "groups": ["admin", "readers"],
            "email": "alice@example.com",
            "email_verified": true,
            "user": {
                "profile": {
                    "name": "Alice",
                    "roles": [
                        {"id": "r1", "display_name": "Admin"},
                        {"id": "r2", "display_name": "Editor"}
                    ]
                }
            }
        });
        let claims = flatten_federation_claims(&json).unwrap();
        assert_eq!(*claims.get("sub").unwrap(), vec!["user123"]);
        assert_eq!(
            *claims.get("aud").unwrap(),
            vec!["my-client", "other-client"]
        );
        assert_eq!(*claims.get("groups").unwrap(), vec!["admin", "readers"]);
        assert_eq!(*claims.get("email_verified").unwrap(), vec!["true"]);
        assert_eq!(*claims.get("user.profile.name").unwrap(), vec!["Alice"]);
        assert_eq!(*claims.get("user.profile.roles.0.id").unwrap(), vec!["r1"]);
        assert_eq!(
            *claims.get("user.profile.roles.0.display_name").unwrap(),
            vec!["Admin"]
        );
        assert_eq!(
            *claims.get("user.profile.roles.1.display_name").unwrap(),
            vec!["Editor"]
        );
    }

    #[test]
    fn flatten_empty_array_is_noop() {
        let json = serde_json::json!({"groups": []});
        let claims = flatten_federation_claims(&json).unwrap();
        assert!(!claims.contains_key("groups"));
    }
}
