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
//! # Create endpoint group

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::{EndpointGroup, EndpointGroupCreate};

use crate::entity::endpoint_group as db_endpoint_group;

/// Creates a new endpoint group.
///
/// # Parameters
/// - `db`: The database connection.
/// - `endpoint_group`: The endpoint group creation parameters.
///
/// # Returns
/// A `Result` containing the created `EndpointGroup`, or an `Error`.
pub async fn create(
    db: &DatabaseConnection,
    endpoint_group: EndpointGroupCreate,
) -> Result<EndpointGroup, CatalogProviderError> {
    TryInto::<db_endpoint_group::ActiveModel>::try_into(endpoint_group)?
        .insert(db)
        .await
        .context("creating endpoint group")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::json;

    use super::super::tests::get_endpoint_group_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_endpoint_group_mock("eg-1")]])
            .into_connection();

        let req = EndpointGroupCreate {
            id: Some("eg-1".into()),
            name: "group".into(),
            description: Some("description".into()),
            filters: HashMap::from([("interface".into(), json!("public"))]),
        };

        let created = create(&db, req).await.unwrap();
        assert_eq!(created.id, "eg-1");
        assert_eq!(created.name, "group");
        assert_eq!(
            created.filters,
            HashMap::from([("interface".to_string(), json!("public"))])
        );
    }
}
