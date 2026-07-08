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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::QueryFilter;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::nonlocal_user as db_nonlocal_user;

/// Update the name of a nonlocal user by finding the record via `user_id`,
/// deleting the old row and inserting a new one.
///
/// `nonlocal_user` uses composite PK `(domain_id, name)`, so a name change
/// requires delete + insert rather than an UPDATE.
///
/// # Parameters
/// - `db`: The database connection (or transaction).
/// - `user_id`: The user ID to locate.
/// - `user_domain_id`: The domain ID for the new record.
/// - `new_name`: The new name for the nonlocal user.
///
/// # Returns
/// A `Result` containing the updated nonlocal user model, or an `Error`.
#[tracing::instrument(skip(db))]
pub async fn update_name<C>(
    db: &C,
    user_id: &str,
    domain_id: &str,
    new_name: &str,
) -> Result<db_nonlocal_user::Model, IdentityProviderError>
where
    C: ConnectionTrait,
{
    let nonlocal = db_nonlocal_user::Entity::find()
        .filter(db_nonlocal_user::Column::UserId.eq(user_id))
        .one(db)
        .await
        .context("fetching nonlocal user for name update")?;

    let nonlocal = nonlocal.ok_or(IdentityProviderError::UserNotFound(user_id.to_string()))?;

    db_nonlocal_user::Entity::delete::<db_nonlocal_user::ActiveModel>(nonlocal.clone().into())
        .exec(db)
        .await
        .context("deleting old nonlocal user entry for rename")?;

    Ok(db_nonlocal_user::ActiveModel {
        domain_id: Set(domain_id.to_string()),
        name: Set(new_name.to_string()),
        user_id: Set(user_id.to_string()),
    }
    .insert(db)
    .await
    .context("inserting updated nonlocal user entry")?)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use crate::nonlocal_user::tests::get_nonlocal_user_mock;

    use super::*;

    #[tokio::test]
    async fn test_update_nonlocal_user_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. Find nonlocal user by user_id
            .append_query_results([vec![get_nonlocal_user_mock("1")]])
            // 2. Delete old nonlocal user (PK change means we can't use UPDATE)
            .append_exec_results([sea_orm::MockExecResult {
                rows_affected: 1,
                last_insert_id: 0,
                ..Default::default()
            }])
            // 3. Insert new nonlocal user with updated name
            .append_query_results([vec![db_nonlocal_user::Model {
                domain_id: "foo_domain".into(),
                name: "new_name".into(),
                user_id: "1".into(),
            }]])
            .into_connection();

        let result = update_name(&db, "1", "foo_domain", "new_name").await;
        assert!(result.is_ok(), "update should succeed: {:?}", result.err());
        assert_eq!(result.unwrap().name, "new_name");
    }
}
