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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::{Region, RegionCreate};

use crate::entity::region as db_region;

/// Creates a new region.
///
/// # Parameters
/// - `db`: The database connection.
/// - `region`: The region creation parameters.
///
/// # Returns
/// A `Result` containing the created `Region`, or an `Error`.
pub async fn create(
    db: &DatabaseConnection,
    region: RegionCreate,
) -> Result<Region, CatalogProviderError> {
    TryInto::<db_region::ActiveModel>::try_into(region)?
        .insert(db)
        .await
        .context("creating region")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_region::Model {
                id: "region-1".into(),
                description: "Region One".into(),
                parent_region_id: None,
                extra: Some(r#"{"key":"value"}"#.into()),
            }]])
            .into_connection();

        let region_create = RegionCreate {
            id: Some("region-1".to_string()),
            description: Some("Region One".to_string()),
            parent_region_id: None,
            extra: HashMap::from([("key".into(), json!("value"))]),
        };

        let created = create(&db, region_create).await.unwrap();

        assert_eq!(created.id, "region-1");
        assert_eq!(created.description.as_deref(), Some("Region One"));
        assert_eq!(
            created.extra,
            HashMap::from([("key".to_string(), json!("value"))])
        );
    }

    #[tokio::test]
    async fn test_create_with_parent() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_region::Model {
                id: "child".into(),
                description: String::new(),
                parent_region_id: Some("parent".into()),
                extra: None,
            }]])
            .into_connection();

        let region_create = RegionCreate {
            id: Some("child".to_string()),
            description: None,
            parent_region_id: Some("parent".to_string()),
            extra: HashMap::new(),
        };

        let created = create(&db, region_create).await.unwrap();

        assert_eq!(created.id, "child");
        // Empty DB description is normalized to None on the domain type.
        assert_eq!(created.description, None);
        assert_eq!(created.parent_region_id.as_deref(), Some("parent"));
    }
}
