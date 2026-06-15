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
//! # Get access rule

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::application_credential::*;

use crate::entity::{access_rule as db_access_rule, prelude::AccessRule as DbAccessRule};

/// Get a user's access rule by its (external) ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The ID of the user owning the access rule.
/// - `id`: The (external) ID of the access rule.
///
/// # Returns
/// A `Result` containing an `Option` with the `AccessRule` if found, or an
/// `Error`.
pub async fn get<U: AsRef<str>, I: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    id: I,
) -> Result<Option<AccessRule>, ApplicationCredentialProviderError> {
    DbAccessRule::find()
        .filter(db_access_rule::Column::ExternalId.eq(id.as_ref()))
        .filter(db_access_rule::Column::UserId.eq(user_id.as_ref()))
        .one(db)
        .await
        .context("fetching access rule by id")?
        .map(TryInto::try_into)
        .transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_access_rule_mock;
    use super::*;
    use crate::entity::access_rule;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_access_rule_mock(1, "rule_id")]])
            .into_connection();

        let result = get(&db, "user_id", "rule_id").await.unwrap();
        assert_eq!(
            result,
            Some(AccessRule {
                id: "rule_id".into(),
                path: Some("/v2.1/servers".into()),
                method: Some("POST".into()),
                service: Some("compute".into()),
            })
        );
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<access_rule::Model>::new()])
            .into_connection();

        let result = get(&db, "user_id", "missing").await.unwrap();
        assert_eq!(result, None);
    }
}
