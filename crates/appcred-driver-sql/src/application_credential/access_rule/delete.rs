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
//! # Delete access rule

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core::error::DbContextExt;

use crate::entity::{
    access_rule as db_access_rule,
    application_credential_access_rule as db_application_credential_access_rule,
    prelude::{
        AccessRule as DbAccessRule,
        ApplicationCredentialAccessRule as DbApplicationCredentialAccessRule,
    },
};

/// Delete a user's access rule by its (external) ID.
///
/// The access rule must not be referenced by any application credential;
/// otherwise an `AccessRuleInUse` error is returned (deleting it would silently
/// strip the credential's restriction).
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The ID of the user owning the access rule.
/// - `id`: The (external) ID of the access rule.
///
/// # Returns
/// A `Result` containing `()` or an `Error` (`AccessRuleNotFound` if no such
/// rule exists, `AccessRuleInUse` if it is still attached to a credential).
pub async fn delete<U: AsRef<str>, I: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    id: I,
) -> Result<(), ApplicationCredentialProviderError> {
    let rule = DbAccessRule::find()
        .filter(db_access_rule::Column::ExternalId.eq(id.as_ref()))
        .filter(db_access_rule::Column::UserId.eq(user_id.as_ref()))
        .one(db)
        .await
        .context("fetching access rule for delete")?
        .ok_or_else(|| {
            ApplicationCredentialProviderError::AccessRuleNotFound(id.as_ref().to_string())
        })?;

    // Refuse to delete a rule that is still attached to an application
    // credential.
    let in_use = DbApplicationCredentialAccessRule::find()
        .filter(db_application_credential_access_rule::Column::AccessRuleId.eq(rule.id))
        .all(db)
        .await
        .context("checking whether access rule is in use")?;
    if !in_use.is_empty() {
        return Err(ApplicationCredentialProviderError::AccessRuleInUse(
            id.as_ref().to_string(),
        ));
    }

    rule.delete(db).await.context("deleting access rule")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use super::super::tests::get_access_rule_mock;
    use super::*;
    use crate::entity::access_rule;

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. fetch the existing rule
            .append_query_results([vec![get_access_rule_mock(1, "rule_id")]])
            // 2. usage check returns no relations
            .append_query_results([Vec::<db_application_credential_access_rule::Model>::new()])
            // 3. the DELETE
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        let result = delete(&db, "user_id", "rule_id").await;
        assert!(result.is_ok(), "delete failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<access_rule::Model>::new()])
            .into_connection();

        let result = delete(&db, "user_id", "missing").await;
        assert!(matches!(
            result,
            Err(ApplicationCredentialProviderError::AccessRuleNotFound(_))
        ));
    }

    #[tokio::test]
    async fn test_delete_in_use() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_access_rule_mock(1, "rule_id")]])
            .append_query_results([vec![db_application_credential_access_rule::Model {
                application_credential_id: 1,
                access_rule_id: 1,
            }]])
            .into_connection();

        let result = delete(&db, "user_id", "rule_id").await;
        assert!(matches!(
            result,
            Err(ApplicationCredentialProviderError::AccessRuleInUse(_))
        ));
    }
}
