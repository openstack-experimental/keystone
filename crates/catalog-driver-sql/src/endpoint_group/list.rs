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
//! # List endpoint groups

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::*;

use crate::entity::{
    endpoint_group as db_endpoint_group, prelude::EndpointGroup as DbEndpointGroup,
};

/// Lists endpoint groups.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters for listing endpoint groups.
///
/// # Returns
/// A `Result` containing a vector of `EndpointGroup`s, or a
/// `CatalogProviderError`.
pub async fn list(
    db: &DatabaseConnection,
    params: &EndpointGroupListParameters,
) -> Result<Vec<EndpointGroup>, CatalogProviderError> {
    let mut select = DbEndpointGroup::find();

    if let Some(name) = &params.name {
        select = select.filter(db_endpoint_group::Column::Name.eq(name));
    }

    select
        .all(db)
        .await
        .context("fetching endpoint groups")?
        .into_iter()
        .map(TryInto::<EndpointGroup>::try_into)
        .collect()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_endpoint_group_mock;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_endpoint_group_mock("eg-1"),
                get_endpoint_group_mock("eg-2"),
            ]])
            .into_connection();

        let groups = list(&db, &EndpointGroupListParameters::default())
            .await
            .unwrap();
        assert_eq!(groups.len(), 2);
    }
}
