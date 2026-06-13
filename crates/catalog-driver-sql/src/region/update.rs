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
//! # Update Region

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::{Region, RegionUpdate};

use crate::entity::{prelude::Region as DbRegion, region as db_region};

/// Updates an existing region.
///
/// Only the fields set in `region` are changed; the rest are left as-is.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the region to update.
/// - `region`: The fields to change.
///
/// # Returns
/// A `Result` containing the updated `Region`, or an `Error` (including
/// `RegionNotFound` if no region with that ID exists).
pub async fn update<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
    region: RegionUpdate,
) -> Result<Region, CatalogProviderError> {
    // Fetch the existing region; error if it does not exist.
    let existing = DbRegion::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching region for update")?
        .ok_or_else(|| CatalogProviderError::RegionNotFound(id.as_ref().to_string()))?;

    // Start from the existing row, then overwrite only the provided fields.
    let mut update_model: db_region::ActiveModel = existing.into();

    if let Some(description) = region.description {
        update_model.description = Set(description);
    }
    if let Some(parent_region_id) = region.parent_region_id {
        update_model.parent_region_id = Set(Some(parent_region_id));
    }
    // The provider has already merged `extra`; the driver only persists it.
    if let Some(extra) = region.extra {
        update_model.extra = Set(Some(serde_json::to_string(&extra)?));
    }

    update_model
        .update(db)
        .await
        .context("updating region")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_region_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. fetch the existing region
            .append_query_results([vec![get_region_mock("1")]])
            // 2. the UPDATE returns the updated row
            .append_query_results([vec![get_region_mock("1")]])
            .into_connection();

        let req = RegionUpdate {
            description: Some("new description".to_string()),
            ..Default::default()
        };

        let result = update(&db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_not_found() {
        // No region rows returned → update should report RegionNotFound.
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_region::Model>::new()])
            .into_connection();

        let result = update(&db, "missing", RegionUpdate::default()).await;
        assert!(matches!(
            result,
            Err(CatalogProviderError::RegionNotFound(_))
        ));
    }
}
