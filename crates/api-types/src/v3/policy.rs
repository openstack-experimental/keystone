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
//! # Legacy policy (`/v3/policies`) API types.
//!
//! The `blob` asymmetry between request and response types is deliberate and
//! matches python keystone:
//!
//! * **Requests** accept a `String` only, per `keystone/policy/schema.py`
//!   (`{'blob': {'type': 'string'}}`). An object-valued `blob` is a 400.
//! * **Responses** carry an arbitrary JSON value, because the stored column
//!   round-trips whatever was written and rows created by older python
//!   keystone releases may hold objects.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

/// Build the OPA policy input for a policy resource from an explicit
/// allowlist of non-sensitive fields.
///
/// # Security Note
///
/// Policy documents are opaque caller-supplied data: `blob` holds the
/// document itself and `extra` holds arbitrary unknown properties, either of
/// which may contain secrets a caller chose to put there. No `.rego` rule in
/// `policy/policy/` reads them, and an external OPA can persist policy input
/// through decision logging, so the input is **constructed** from known-safe
/// fields rather than filtered — a denylist would have to be extended every
/// time a field is added, and could never cover `extra`'s open key space.
fn policy_input(id: Option<&str>, r#type: Option<&str>) -> Value {
    let mut input = serde_json::Map::new();
    input.insert("id".to_string(), serde_json::json!(id));
    input.insert("type".to_string(), serde_json::json!(r#type));
    Value::Object(input)
}

/// The policy data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Policy {
    /// Policy ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// The MIME media type of the serialized policy blob.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: String,

    /// The policy rule set itself, as a serialized blob.
    ///
    /// Any JSON value: normally the string the caller supplied on create, but
    /// an object for rows written by older python keystone releases. No
    /// `value_type` override here on purpose — `serde_json::Value`'s native
    /// utoipa mapping is an unconstrained `AnyValue`, whereas `Object` would
    /// document `type: object` and make a generated client reject the ordinary
    /// string case.
    pub blob: Value,

    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Policy {
    /// Non-sensitive policy-input projection. See [`policy_input`].
    #[must_use]
    pub fn to_policy_input(&self) -> Value {
        policy_input(Some(&self.id), Some(&self.r#type))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct PolicyResponse {
    /// Policy object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub policy: Policy,
}

/// Policies.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct PolicyList {
    /// Collection of policy objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub policies: Vec<Policy>,

    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<crate::Link>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct PolicyListParameters {
    /// Filters the response by a MIME media type for the serialized policy
    /// blob. For example, `application/json`. Exact match.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: Option<String>,
}

impl PolicyListParameters {
    /// Non-sensitive policy-input projection. See [`policy_input`].
    #[must_use]
    pub fn to_policy_input(&self) -> Value {
        policy_input(None, self.r#type.as_deref())
    }
}

/// Policy create request body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct PolicyCreate {
    /// The MIME media type of the serialized policy blob.
    ///
    /// Required, but only length-capped: python keystone's schema is
    /// `{'type': 'string', 'maxLength': 255}`, so the empty string is valid.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: String,

    /// The policy rule set itself, as a serialized blob. Required, and a
    /// string only — see the module docs.
    pub blob: String,

    /// Ignored: a caller-supplied `id` on create is discarded and a fresh
    /// UUID assigned, matching python keystone's `_assign_unique_id`.
    ///
    /// Declared explicitly (rather than left to `extra`'s `#[serde(flatten)]`)
    /// so it is *consumed* here instead of being silently persisted as an
    /// extra property.
    ///
    /// Typed as an arbitrary `Value`, not `String`: upstream never validates
    /// it — `id` is not in `_policy_properties`, so it arrives as an
    /// unconstrained `additionalProperties` entry and is then overwritten. A
    /// `{"id": 123}` body is therefore a 201 upstream, and must not be a 400
    /// here.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,

    /// Extra attributes for the policy.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl PolicyCreate {
    /// Non-sensitive policy-input projection. See [`policy_input`].
    ///
    /// `id` is deliberately absent: it does not exist yet at create time.
    #[must_use]
    pub fn to_policy_input(&self) -> Value {
        policy_input(None, Some(&self.r#type))
    }
}

/// New policy creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct PolicyCreateRequest {
    /// Policy object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub policy: PolicyCreate,
}

/// Update policy data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct PolicyUpdate {
    /// New MIME media type of the serialized policy blob.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: Option<String>,

    /// New policy blob. String only — see the module docs.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,

    /// Only accepted when equal to the `{policy_id}` path segment; a
    /// different value is a 400 ("Cannot change policy ID"), matching python
    /// keystone's `Manager.update_policy`. Never persisted.
    ///
    /// Declared explicitly so it is consumed here rather than landing in
    /// `extra`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Extra attributes for the policy, merged into the stored properties.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl PolicyUpdate {
    /// Non-sensitive policy-input projection. See [`policy_input`].
    #[must_use]
    pub fn to_policy_input(&self) -> Value {
        policy_input(self.id.as_deref(), self.r#type.as_deref())
    }

    /// Whether the request body carries no change at all.
    ///
    /// Python keystone's `policy_update` schema sets `minProperties: 1`, so an
    /// empty `{"policy": {}}` document is a 400 rather than a no-op.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.r#type.is_none() && self.blob.is_none() && self.id.is_none() && self.extra.is_empty()
    }
}

/// Policy update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct PolicyUpdateRequest {
    /// Policy object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub policy: PolicyUpdate,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OPA projection is an allowlist: neither the blob nor any extra
    /// property — including deliberately secret-shaped and *nested* ones —
    /// can appear in it.
    #[test]
    fn test_policy_input_is_allowlisted() {
        let policy = Policy {
            id: "pid".into(),
            r#type: "application/json".into(),
            blob: serde_json::json!("s3cr3t-blob"),
            extra: HashMap::from([
                ("password".into(), serde_json::json!("hunter2")),
                (
                    "nested".into(),
                    serde_json::json!({"totp_seed": "AAAA", "deep": {"secret": "x"}}),
                ),
            ]),
        };

        let input = policy.to_policy_input();
        assert_eq!(
            input,
            serde_json::json!({"id": "pid", "type": "application/json"})
        );
        let rendered = input.to_string();
        for needle in ["s3cr3t-blob", "hunter2", "AAAA", "password", "totp_seed"] {
            assert!(
                !rendered.contains(needle),
                "{needle} leaked into {rendered}"
            );
        }
    }

    #[test]
    fn test_create_policy_input_has_no_id() {
        let create = PolicyCreate {
            r#type: "text/plain".into(),
            blob: "b".into(),
            id: Some("ignored".into()),
            extra: HashMap::from([("blob".into(), serde_json::json!("sneaky"))]),
        };
        assert_eq!(
            create.to_policy_input(),
            serde_json::json!({"id": null, "type": "text/plain"})
        );
    }

    #[test]
    fn test_update_is_empty() {
        assert!(PolicyUpdate::default().is_empty());
        assert!(
            !PolicyUpdate {
                r#type: Some("x".into()),
                ..Default::default()
            }
            .is_empty()
        );
        assert!(
            !PolicyUpdate {
                extra: HashMap::from([("k".into(), serde_json::json!(1))]),
                ..Default::default()
            }
            .is_empty()
        );
    }

    /// A caller-supplied `id` must bind to the explicit field, not be
    /// swallowed by `extra`'s flatten.
    #[test]
    fn test_create_id_is_not_captured_by_extra() {
        let req: PolicyCreateRequest = serde_json::from_value(serde_json::json!({
            "policy": {"type": "t", "blob": "b", "id": "caller-supplied", "other": 1}
        }))
        .unwrap();

        assert_eq!(req.policy.id, Some(serde_json::json!("caller-supplied")));
        assert!(!req.policy.extra.contains_key("id"));
        assert_eq!(req.policy.extra.get("other"), Some(&serde_json::json!(1)));
    }

    /// Upstream never validates `id` on create — it is an unconstrained
    /// additional property that `_assign_unique_id` overwrites — so a
    /// non-string `id` must deserialize rather than 400.
    #[test]
    fn test_create_accepts_non_string_id() {
        for id in [
            serde_json::json!(123),
            serde_json::json!({"nested": true}),
            serde_json::json!(null),
        ] {
            let req: PolicyCreateRequest = serde_json::from_value(serde_json::json!({
                "policy": {"type": "t", "blob": "b", "id": id}
            }))
            .unwrap_or_else(|e| panic!("id {id} must be accepted on create: {e}"));
            assert!(!req.policy.extra.contains_key("id"));
        }
    }

    /// `type` is required but may be empty: upstream's schema is
    /// `{'type': 'string', 'maxLength': 255}`, with no `minLength`.
    #[test]
    fn test_empty_type_is_valid() {
        let req: PolicyCreateRequest = serde_json::from_value(serde_json::json!({
            "policy": {"type": "", "blob": "b"}
        }))
        .unwrap();
        assert_eq!(req.policy.r#type, "");

        #[cfg(feature = "validate")]
        {
            use validator::Validate;
            assert!(
                req.validate().is_ok(),
                "an empty `type` must pass validation"
            );
        }
    }

    /// An object-valued `blob` fails deserialization, which the router turns
    /// into a 400.
    #[test]
    fn test_object_blob_is_rejected() {
        let err = serde_json::from_value::<PolicyCreateRequest>(serde_json::json!({
            "policy": {"type": "t", "blob": {"foobar_user": ["role:compute-user"]}}
        }));
        assert!(err.is_err(), "object-valued blob must not deserialize");
    }
}
