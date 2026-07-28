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
//! # Create policy

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::policy_store::PolicyStoreProviderError;
use openstack_keystone_core_types::policy_store::{Policy, PolicyCreate};

use crate::entity::policy as db_policy;

/// Creates a new policy.
///
/// # Parameters
/// - `db`: The database connection.
/// - `policy`: The policy creation parameters.
///
/// # Returns
/// A `Result` containing the created `Policy`, or an `Error`.
pub async fn create(
    db: &DatabaseConnection,
    policy: PolicyCreate,
) -> Result<Policy, PolicyStoreProviderError> {
    TryInto::<db_policy::ActiveModel>::try_into(policy)?
        .insert(db)
        .await
        .context("creating policy")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::{Value, json};

    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_policy::Model {
                id: "policy-1".into(),
                r#type: "application/json".into(),
                blob: r#""blob text""#.into(),
                extra: Some(r#"{"key":"value"}"#.into()),
            }]])
            .into_connection();

        let created = create(
            &db,
            PolicyCreate {
                id: Some("policy-1".into()),
                r#type: "application/json".into(),
                blob: Value::String("blob text".into()),
                extra: HashMap::from([("key".into(), json!("value"))]),
            },
        )
        .await
        .unwrap();

        assert_eq!(created.id, "policy-1");
        assert_eq!(created.r#type, "application/json");
        assert_eq!(created.blob, Value::String("blob text".into()));
        assert_eq!(
            created.extra,
            HashMap::from([("key".to_string(), json!("value"))])
        );
    }

    /// A missing ID is a programming error, not something the driver papers
    /// over: the service layer has already announced the ID in the audit
    /// event by the time the backend is called.
    #[tokio::test]
    async fn test_create_without_id_is_rejected() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_policy::Model>::new()])
            .into_connection();

        let result = create(
            &db,
            PolicyCreate {
                id: None,
                r#type: "text/plain".into(),
                blob: Value::String("x".into()),
                extra: HashMap::new(),
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(openstack_keystone_core::policy_store::PolicyStoreProviderError::Driver(_))
        ));
        assert!(
            db.into_transaction_log().is_empty(),
            "nothing may be written without a service-assigned ID"
        );
    }
}
