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

use std::collections::HashMap;

use serde_json::Value;

use openstack_keystone_core_types::policy_store as provider_types;

use crate::v3::policy as api_types;

/// Normalize an additional-property name the way python keystone's
/// `ResourceBase._normalize_arg` does: `:` and `-` both become `_`.
///
/// Applied on create only. Python keystone runs `_normalize_dict` over the
/// `POST` body but not over the `PATCH` body, so this asymmetry is faithful,
/// not an oversight.
fn normalize_extra_keys(extra: HashMap<String, Value>) -> HashMap<String, Value> {
    extra
        .into_iter()
        .map(|(k, v)| (k.replace([':', '-'], "_"), v))
        .collect()
}

impl From<provider_types::Policy> for api_types::Policy {
    fn from(value: provider_types::Policy) -> Self {
        Self {
            id: value.id,
            r#type: value.r#type,
            blob: value.blob,
            extra: value.extra,
        }
    }
}

impl From<api_types::PolicyListParameters> for provider_types::PolicyListParameters {
    fn from(value: api_types::PolicyListParameters) -> Self {
        Self {
            r#type: value.r#type,
            pagination: Default::default(),
        }
    }
}

impl From<api_types::PolicyCreateRequest> for provider_types::PolicyCreate {
    fn from(value: api_types::PolicyCreateRequest) -> Self {
        Self {
            // `id` is intentionally dropped: python keystone's
            // `_assign_unique_id` overwrites any caller-supplied value, and
            // the service layer assigns the real one.
            id: None,
            r#type: value.policy.r#type,
            blob: Value::String(value.policy.blob),
            extra: normalize_extra_keys(value.policy.extra),
        }
    }
}

impl From<api_types::PolicyUpdateRequest> for provider_types::PolicyUpdate {
    fn from(value: api_types::PolicyUpdateRequest) -> Self {
        Self {
            r#type: value.policy.r#type,
            blob: value.policy.blob.map(Value::String),
            // `id` is validated against the path by the handler and never
            // persisted.
            extra: value.policy.extra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_conv_drops_id_and_wraps_blob() {
        let create: provider_types::PolicyCreate = api_types::PolicyCreateRequest {
            policy: api_types::PolicyCreate {
                r#type: "application/json".into(),
                blob: "raw".into(),
                id: Some(serde_json::json!("caller-supplied")),
                extra: HashMap::new(),
            },
        }
        .into();

        assert_eq!(create.id, None, "caller-supplied id must be discarded");
        assert_eq!(create.blob, Value::String("raw".into()));
        assert_eq!(create.r#type, "application/json");
    }

    /// Python keystone normalizes `:`/`-` in additional-property names on
    /// create.
    #[test]
    fn test_create_conv_normalizes_extra_keys() {
        let create: provider_types::PolicyCreate = api_types::PolicyCreateRequest {
            policy: api_types::PolicyCreate {
                r#type: "t".into(),
                blob: "b".into(),
                id: None,
                extra: HashMap::from([
                    ("x-dash".into(), serde_json::json!(1)),
                    ("x:colon".into(), serde_json::json!(2)),
                    ("plain".into(), serde_json::json!(3)),
                ]),
            },
        }
        .into();

        assert_eq!(create.extra.get("x_dash"), Some(&serde_json::json!(1)));
        assert_eq!(create.extra.get("x_colon"), Some(&serde_json::json!(2)));
        assert_eq!(create.extra.get("plain"), Some(&serde_json::json!(3)));
        assert!(!create.extra.contains_key("x-dash"));
    }

    /// PATCH does not normalize, matching python keystone.
    #[test]
    fn test_update_conv_preserves_extra_keys_and_drops_id() {
        let update: provider_types::PolicyUpdate = api_types::PolicyUpdateRequest {
            policy: api_types::PolicyUpdate {
                r#type: None,
                blob: Some("nb".into()),
                id: Some("pid".into()),
                extra: HashMap::from([("x-dash".into(), serde_json::json!(1))]),
            },
        }
        .into();

        assert_eq!(update.blob, Some(Value::String("nb".into())));
        assert!(update.extra.contains_key("x-dash"));
        assert!(!update.extra.contains_key("id"));
    }
}
