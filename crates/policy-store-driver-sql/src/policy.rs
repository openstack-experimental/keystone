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

use sea_orm::entity::*;
use serde_json::Value;
use tracing::error;

use openstack_keystone_core::policy_store::PolicyStoreProviderError;
use openstack_keystone_core_types::policy_store::*;

use crate::entity::policy as db_policy;

mod create;
mod delete;
mod get;
mod list;
mod update;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::list;
pub use update::update;

/// Decode a `JsonBlob`-style column into a map of extra properties.
///
/// A malformed value is an **error**, not an empty map. The catalog driver
/// logs-and-drops for `region.extra`, but that is unsafe here: `update()`
/// reads the stored extras, merges the patch over them, and writes the result
/// back, so swallowing a decode failure would silently replace a row's
/// existing properties with `{}` — permanent data loss on an ordinary PATCH.
/// Python keystone's `JsonBlob.process_result_value` is a bare `json.loads`
/// and raises here too.
fn decode_extra(raw: Option<&String>) -> Result<HashMap<String, Value>, PolicyStoreProviderError> {
    match raw {
        Some(extra) if extra != "{}" => serde_json::from_str::<HashMap<String, Value>>(extra)
            .map_err(|e| {
                error!("failed to deserialize policy extra: {e}");
                PolicyStoreProviderError::Serde { source: e }
            }),
        _ => Ok(HashMap::new()),
    }
}

impl TryFrom<db_policy::Model> for Policy {
    type Error = PolicyStoreProviderError;

    /// Tries to convert a database policy model into a domain policy.
    ///
    /// # Parameters
    /// - `value`: The database policy model.
    ///
    /// # Returns
    /// A `Result` containing the `Policy`, or a `PolicyStoreProviderError`.
    fn try_from(value: db_policy::Model) -> Result<Self, Self::Error> {
        // `blob` is `NOT NULL` and always JSON-encoded by whoever wrote it
        // (python keystone's `JsonBlob.process_bind_param` does
        // `json.dumps`). A row that fails to decode is corrupt data, and
        // python keystone raises there too, so propagate rather than guess.
        let blob: Value = serde_json::from_str(&value.blob)?;

        let mut builder = PolicyBuilder::default();
        builder.id(value.id.clone());
        builder.r#type(value.r#type.clone());
        builder.blob(blob);
        builder.extra(decode_extra(value.extra.as_ref())?);

        Ok(builder.build()?)
    }
}

impl TryFrom<PolicyCreate> for db_policy::ActiveModel {
    type Error = PolicyStoreProviderError;

    /// Tries to convert policy creation parameters into a database active
    /// model.
    ///
    /// # Parameters
    /// - `value`: The policy creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the `ActiveModel`, or a
    /// `PolicyStoreProviderError`.
    fn try_from(value: PolicyCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            // The service layer always assigns the ID before calling the
            // backend, so that the audit event carries it. No fallback here:
            // a second generation site would silently diverge from the ID the
            // audit record already announced.
            id: Set(value.id.ok_or_else(|| {
                PolicyStoreProviderError::Driver(
                    "policy id must be assigned by the service layer".into(),
                )
            })?),
            r#type: Set(value.r#type),
            blob: Set(serde_json::to_string(&value.blob)?),
            extra: Set(Some(serde_json::to_string(&value.extra)?)),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::entity::policy;

    /// A stored policy whose `blob` is a JSON *string*, which is what the API
    /// accepts today.
    pub fn get_policy_mock<I: Into<String>>(id: I) -> policy::Model {
        policy::Model {
            id: id.into(),
            r#type: "application/json".into(),
            blob: r#""{'foobar_user': 'role:compute-user'}""#.to_string(),
            extra: Some(r#"{"key": "value"}"#.to_string()),
        }
    }

    /// A stored policy whose `blob` is a JSON *object*, as written by older
    /// python keystone releases before the create schema was narrowed to a
    /// string. Such rows must keep deserializing.
    pub fn get_legacy_object_blob_policy_mock<I: Into<String>>(id: I) -> policy::Model {
        policy::Model {
            id: id.into(),
            r#type: "application/json".into(),
            blob: r#"{"foobar_user":["role:compute-user"]}"#.to_string(),
            extra: None,
        }
    }

    #[test]
    fn test_string_blob_round_trips() {
        let policy: Policy = get_policy_mock("1").try_into().unwrap();
        assert_eq!(policy.id, "1");
        assert_eq!(policy.r#type, "application/json");
        assert_eq!(
            policy.blob,
            Value::String("{'foobar_user': 'role:compute-user'}".into())
        );
        assert_eq!(
            policy.extra,
            HashMap::from([("key".to_string(), serde_json::json!("value"))])
        );
    }

    #[test]
    fn test_legacy_object_blob_round_trips() {
        let policy: Policy = get_legacy_object_blob_policy_mock("2").try_into().unwrap();
        assert_eq!(
            policy.blob,
            serde_json::json!({"foobar_user":["role:compute-user"]})
        );
        assert!(policy.extra.is_empty());
    }

    /// `blob` is JSON-encoded on write, exactly as python keystone's
    /// `JsonBlob` type decorator does, so a string blob is stored quoted.
    #[test]
    fn test_create_encodes_blob_as_json() {
        let model: db_policy::ActiveModel = PolicyCreate {
            id: Some("pid".into()),
            r#type: "application/json".into(),
            blob: Value::String("raw text".into()),
            extra: HashMap::new(),
        }
        .try_into()
        .unwrap();

        // Match the typed `sea_orm::Value` rather than its `to_string()`
        // rendering: the `Display` form adds its own quoting/escaping, so
        // asserting on it tests sea-orm's formatting instead of what this
        // driver actually writes.
        let stored = match model.blob.into_value() {
            Some(sea_orm::Value::String(Some(s))) => s.to_string(),
            other => panic!("blob must bind as a non-null string, got {other:?}"),
        };

        // python keystone's `JsonBlob.process_bind_param` is `json.dumps`, so
        // a string blob is stored as a *quoted* JSON string.
        assert_eq!(stored, r#""raw text""#);
        assert_eq!(
            serde_json::from_str::<Value>(&stored).unwrap(),
            Value::String("raw text".into()),
            "the stored bytes must decode back to the original value"
        );
    }

    /// A corrupt (non-JSON) `blob` column is an error, not a silent
    /// misrepresentation.
    #[test]
    fn test_malformed_blob_is_error() {
        let model = policy::Model {
            id: "3".into(),
            r#type: "application/json".into(),
            blob: "not json at all".into(),
            extra: None,
        };
        assert!(Policy::try_from(model).is_err());
    }

    /// A malformed `extra` must surface as an error rather than decoding to an
    /// empty map: `update()` writes the decoded extras back, so silently
    /// yielding `{}` would destroy the row's stored properties on the next
    /// PATCH.
    #[test]
    fn test_malformed_extra_is_error() {
        let model = policy::Model {
            id: "4".into(),
            r#type: "application/json".into(),
            blob: r#""x""#.into(),
            extra: Some("{not json".into()),
        };
        assert!(matches!(
            Policy::try_from(model),
            Err(PolicyStoreProviderError::Serde { .. })
        ));
    }
}
