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
//! # Update Endpoint Group

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::{EndpointGroup, EndpointGroupUpdate};

use crate::entity::{
    endpoint_group as db_endpoint_group, prelude::EndpointGroup as DbEndpointGroup,
};

/// Updates an existing endpoint group.
///
/// Only the fields set in `endpoint_group` are changed; the rest are left
/// as-is.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the endpoint group to update.
/// - `endpoint_group`: The fields to change.
///
/// # Returns
/// A `Result` containing the updated `EndpointGroup`, or an `Error` (including
/// `EndpointGroupNotFound` if no endpoint group with that ID exists).
pub async fn update<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
    endpoint_group: EndpointGroupUpdate,
) -> Result<EndpointGroup, CatalogProviderError> {
    let existing = DbEndpointGroup::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching endpoint group for update")?
        .ok_or_else(|| CatalogProviderError::EndpointGroupNotFound(id.as_ref().to_string()))?;

    let mut update_model: db_endpoint_group::ActiveModel = existing.into();

    if let Some(name) = endpoint_group.name {
        update_model.name = Set(name);
    }
    if let Some(description) = endpoint_group.description {
        update_model.description = Set(Some(description));
    }
    if let Some(filters) = endpoint_group.filters {
        update_model.filters = Set(serde_json::to_string(&filters)?);
    }

    update_model
        .update(db)
        .await
        .context("updating endpoint group")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_endpoint_group_mock;
    use super::*;
    use crate::entity::endpoint_group;

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. fetch the existing group
            .append_query_results([vec![get_endpoint_group_mock("eg-1")]])
            // 2. the UPDATE returns the updated row
            .append_query_results([vec![get_endpoint_group_mock("eg-1")]])
            .into_connection();

        let req = EndpointGroupUpdate {
            name: Some("renamed".into()),
            ..Default::default()
        };

        let result = update(&db, "eg-1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<endpoint_group::Model>::new()])
            .into_connection();

        let result = update(&db, "missing", EndpointGroupUpdate::default()).await;
        assert!(matches!(
            result,
            Err(CatalogProviderError::EndpointGroupNotFound(_))
        ));
    }
}
