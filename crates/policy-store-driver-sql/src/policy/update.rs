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
//! # Update policy

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::policy_store::PolicyStoreProviderError;
use openstack_keystone_core_types::policy_store::{Policy, PolicyUpdate};

use crate::entity::{policy as db_policy, prelude::Policy as DbPolicy};

/// Updates an existing policy.
///
/// Only the fields set in `policy` are changed; the rest are left as-is.
/// `extra` is **merged** into the stored value rather than replacing it,
/// mirroring python keystone's `update_policy` (which patches the old dict
/// with the request body before writing it back).
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the policy to update.
/// - `policy`: The fields to change.
///
/// # Returns
/// A `Result` containing the updated `Policy`, or an `Error` (including
/// `PolicyNotFound` if no policy with that ID exists).
pub async fn update<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
    policy: PolicyUpdate,
) -> Result<Policy, PolicyStoreProviderError> {
    let existing = DbPolicy::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching policy for update")?
        .ok_or_else(|| PolicyStoreProviderError::PolicyNotFound(id.as_ref().to_string()))?;

    // Merge the supplied extras over the stored ones (new keys win, omitted
    // stored keys survive).
    let mut extra = super::decode_extra(existing.extra.as_ref())?;
    extra.extend(policy.extra);

    let mut update_model: db_policy::ActiveModel = existing.into();

    if let Some(r#type) = policy.r#type {
        update_model.r#type = Set(r#type);
    }
    if let Some(blob) = policy.blob {
        update_model.blob = Set(serde_json::to_string(&blob)?);
    }
    update_model.extra = Set(Some(serde_json::to_string(&extra)?));

    update_model
        .update(db)
        .await
        .context("updating policy")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::{Value, json};

    use super::super::tests::get_policy_mock;
    use super::*;

    /// PATCHing only `type` must leave `blob` untouched — this is exactly
    /// what tempest's `test_create_update_delete_policy` asserts.
    #[tokio::test]
    async fn test_update_type_only_preserves_blob() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_policy_mock("1")]])
            .append_query_results([vec![db_policy::Model {
                id: "1".into(),
                r#type: "text/plain".into(),
                blob: r#""{'foobar_user': 'role:compute-user'}""#.into(),
                extra: Some(r#"{"key":"value"}"#.into()),
            }]])
            .into_connection();

        let updated = update(
            &db,
            "1",
            PolicyUpdate {
                r#type: Some("text/plain".into()),
                blob: None,
                extra: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.r#type, "text/plain");
        assert_eq!(
            updated.blob,
            Value::String("{'foobar_user': 'role:compute-user'}".into()),
            "blob must survive a type-only PATCH"
        );

        let txns = db.into_transaction_log();
        let sql = &txns[1].statements()[0].sql;
        assert!(sql.contains(r#"UPDATE "policy""#));
    }

    /// Stored extras omitted from the PATCH body survive; supplied keys win.
    #[tokio::test]
    async fn test_update_merges_extra() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_policy::Model {
                id: "1".into(),
                r#type: "application/json".into(),
                blob: r#""b""#.into(),
                extra: Some(r#"{"keep":"me","over":"old"}"#.into()),
            }]])
            .append_query_results([vec![db_policy::Model {
                id: "1".into(),
                r#type: "application/json".into(),
                blob: r#""b""#.into(),
                extra: Some(r#"{"keep":"me","over":"new","add":"x"}"#.into()),
            }]])
            .into_connection();

        update(
            &db,
            "1",
            PolicyUpdate {
                r#type: None,
                blob: None,
                extra: HashMap::from([("over".into(), json!("new")), ("add".into(), json!("x"))]),
            },
        )
        .await
        .unwrap();

        // Pull the bound `extra` parameter out of the UPDATE as a typed
        // `sea_orm::Value`. Rendering the values with `to_string()` and then
        // splitting on single quotes would break on any extra value that
        // itself contains a quote, and asserts on sea-orm's `Display` impl
        // rather than on the bytes this driver binds.
        let txns = db.into_transaction_log();
        let stmt = &txns[1].statements()[0];
        let values = stmt
            .values
            .as_ref()
            .expect("the UPDATE statement binds parameters");
        let extra_json = values
            .0
            .iter()
            .find_map(|v| match v {
                sea_orm::Value::String(Some(s)) if s.starts_with('{') => Some(s.as_str()),
                _ => None,
            })
            .expect("serialized extra is bound as a JSON object string");
        let extra: HashMap<String, Value> = serde_json::from_str(extra_json).unwrap();

        assert_eq!(
            extra.get("keep"),
            Some(&json!("me")),
            "omitted key survives"
        );
        assert_eq!(extra.get("over"), Some(&json!("new")), "supplied key wins");
        assert_eq!(extra.get("add"), Some(&json!("x")), "new key added");
    }

    #[tokio::test]
    async fn test_update_missing_is_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_policy::Model>::new()])
            .into_connection();

        assert!(matches!(
            update(&db, "missing", PolicyUpdate::default()).await,
            Err(PolicyStoreProviderError::PolicyNotFound(_))
        ));
    }
}
