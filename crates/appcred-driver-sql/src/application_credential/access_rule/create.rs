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
//! # Create access rule

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use uuid::Uuid;

use openstack_keystone_core::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::application_credential::*;

use crate::entity::access_rule as db_access_rule;

/// Create a standalone access rule owned by a user.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The ID of the user owning the access rule.
/// - `rule`: The access rule to create.
///
/// # Returns
/// A `Result` containing the created `AccessRule` or an `Error`.
pub async fn create<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    rule: AccessRuleCreate,
) -> Result<AccessRule, ApplicationCredentialProviderError> {
    db_access_rule::ActiveModel {
        id: NotSet,
        method: Set(rule.method),
        path: Set(rule.path),
        service: Set(rule.service),
        external_id: Set(Some(rule.id.unwrap_or(Uuid::new_v4().simple().to_string()))),
        user_id: Set(Some(user_id.as_ref().to_string())),
    }
    .insert(db)
    .await
    .context("persisting access rule")?
    .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_access_rule_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_access_rule_mock(1, "rule_id")]])
            .into_connection();

        let req = AccessRuleCreate {
            id: Some("rule_id".into()),
            method: Some("POST".into()),
            path: Some("/v2.1/servers".into()),
            service: Some("compute".into()),
        };

        let result = create(&db, "user_id", req).await;
        assert!(result.is_ok(), "create failed: {:?}", result.err());
    }
}
