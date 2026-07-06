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
//! Update group properties.

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::{Group, GroupUpdate};

use crate::entity::group as db_group;

/// Update an existing group.
///
/// # Parameters
/// - `db`: The database connection.
/// - `group_id`: The ID of the group to update.
/// - `group`: The group update request.
///
/// # Returns
/// A `Result` containing the updated `Group` if successful, or an `Error`.
#[tracing::instrument(skip(db))]
pub async fn update(
    db: &DatabaseConnection,
    group_id: &str,
    group: GroupUpdate,
) -> Result<Group, IdentityProviderError> {
    let existing = db_group::Entity::find_by_id(group_id)
        .one(db)
        .await
        .context("fetching group for update")?
        .ok_or_else(|| IdentityProviderError::GroupNotFound(group_id.to_string()))?;

    let mut update_model: db_group::ActiveModel = existing.into();

    if let Some(name) = group.name {
        update_model.name = Set(name);
    }

    if let Some(description) = group.description {
        update_model.description = Set(description);
    }

    // The provider passes the full desired `extra`; the driver only
    // persists it (PUT is a full-replace, not a patch).
    if !group.extra.is_empty() {
        update_model.extra = Set(Some(serde_json::to_string(&group.extra)?));
    }

    let updated: db_group::Model = update_model
        .update(db)
        .await
        .context("updating group entry")?;

    Ok(updated.into())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;
    use crate::group::tests::get_group_mock;

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1")], vec![get_group_mock("1")]])
            .into_connection();

        let req = GroupUpdate {
            name: Some("new_name".into()),
            description: None,
            extra: Default::default(),
        };
        let result = update(&db, "1", req).await.unwrap();
        assert_eq!(result, get_group_mock("1").into());
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_group::Model>::new()])
            .into_connection();

        let req = GroupUpdate {
            name: Some("new_name".into()),
            description: None,
            extra: Default::default(),
        };
        let result = update(&db, "missing", req).await;
        assert!(matches!(
            result,
            Err(IdentityProviderError::GroupNotFound(_))
        ));
    }
}
