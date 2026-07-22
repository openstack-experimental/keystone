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
//! # Get endpoint group

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::EndpointGroup;

use crate::entity::prelude::EndpointGroup as DbEndpointGroup;

/// Gets an endpoint group by ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the endpoint group to retrieve.
///
/// # Returns
/// A `Result` containing an `Option` with the `EndpointGroup` if found, or an
/// `Error`.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<EndpointGroup>, CatalogProviderError> {
    DbEndpointGroup::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching endpoint group by ID")?
        .map(TryInto::try_into)
        .transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_endpoint_group_mock;
    use super::*;
    use crate::entity::endpoint_group;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_endpoint_group_mock("eg-1")]])
            .into_connection();

        let eg = get(&db, "eg-1").await.unwrap().expect("group found");
        assert_eq!(eg.id, "eg-1");
        assert_eq!(eg.name, "group");
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<endpoint_group::Model>::new()])
            .into_connection();

        assert!(get(&db, "missing").await.unwrap().is_none());
    }
}
