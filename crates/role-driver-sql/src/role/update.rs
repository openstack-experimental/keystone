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
//! # Update Role

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::{Role, RoleUpdate};

use crate::entity::{prelude::Role as DbRole, role as db_role};

/// Update an existing role.
///
/// Only the fields set in `role` are changed; the rest are left as-is.
///
/// # Parameters
/// - `db`: The database connection.
/// - `role_id`: The ID of the role to update.
/// - `role`: The fields to change.
///
/// # Returns
/// A `Result` containing the updated `Role`, or an `Error` (including
/// `RoleNotFound` if no role with that ID exists).
pub async fn update<C>(db: &C, role_id: &str, role: RoleUpdate) -> Result<Role, RoleProviderError>
where
    C: ConnectionTrait,
{
    let existing = DbRole::find_by_id(role_id)
        .one(db)
        .await
        .context("fetching role for update")?
        .ok_or_else(|| RoleProviderError::RoleNotFound(role_id.to_string()))?;

    let mut update_model: db_role::ActiveModel = existing.into();

    if let Some(name) = role.name {
        update_model.name = Set(name);
    }
    if let Some(description) = role.description {
        update_model.description = Set(description);
    }
    if !role.extra.is_empty() {
        update_model.extra = Set(Some(serde_json::to_string(&role.extra)?));
    }

    update_model
        .update(db)
        .await
        .context("updating role")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_role_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                vec![get_role_mock("1", "foo")],
                vec![get_role_mock("1", "new_name")],
            ])
            .into_connection();

        let req = RoleUpdate {
            name: Some("new_name".into()),
            description: None,
            extra: Default::default(),
        };
        let result = update(&db, "1", req).await.unwrap();
        assert_eq!(result, get_role_mock("1", "new_name").try_into().unwrap());
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_role::Model>::new()])
            .into_connection();

        let req = RoleUpdate {
            name: Some("new_name".into()),
            description: None,
            extra: Default::default(),
        };
        let result = update(&db, "missing", req).await;
        assert!(matches!(result, Err(RoleProviderError::RoleNotFound(_))));
    }
}
