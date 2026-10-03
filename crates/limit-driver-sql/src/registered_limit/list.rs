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
use sea_orm::query::*;
use sea_orm::{Cursor, SelectModel};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::{RegisteredLimit, RegisteredLimitListParameters};

use crate::entity::{
    prelude::RegisteredLimit as DbRegisteredLimit, registered_limit as db_registered_limit,
};

/// List registered limits.
pub async fn list(
    db: &DatabaseConnection,
    params: &RegisteredLimitListParameters,
) -> Result<Vec<RegisteredLimit>, LimitProviderError> {
    Ok(get_list_query(params)
        .all(db)
        .await
        .context("fetching registered limits")?
        .into_iter()
        .map(Into::into)
        .collect())
}

/// Prepare the paginated query for listing registered limits.
fn get_list_query(
    params: &RegisteredLimitListParameters,
) -> Cursor<SelectModel<db_registered_limit::Model>> {
    let mut select = DbRegisteredLimit::find();
    if let Some(service_id) = &params.service_id {
        select = select.filter(db_registered_limit::Column::ServiceId.eq(service_id));
    }
    if let Some(region_id) = &params.region_id {
        select = select.filter(db_registered_limit::Column::RegionId.eq(region_id));
    }
    if let Some(resource_name) = &params.resource_name {
        select = select.filter(db_registered_limit::Column::ResourceName.eq(resource_name));
    }
    let mut cursor = select.cursor_by(db_registered_limit::Column::Id);
    if let Some(marker) = &params.pagination.marker {
        if params.pagination.page_reverse {
            cursor.before(marker);
        } else {
            cursor.after(marker);
        }
    }
    // Over-fetch by one row so the API layer can tell whether there is
    // another page.
    if let Some(limit) = params.pagination.limit {
        if params.pagination.page_reverse {
            cursor.last(limit + 1);
        } else {
            cursor.first(limit + 1);
        }
    }
    cursor
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;
    use crate::registered_limit::tests::get_mock;

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("1"), get_mock("2")]])
            .into_connection();
        let res = list(
            &db,
            &RegisteredLimitListParameters {
                service_id: Some("srv".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(2, res.len());
        let log = db.into_transaction_log();
        let sql = format!("{:?}", log).replace("\\\"", "\"");
        assert!(sql.contains("\"registered_limit\".\"service_id\" = "));
        assert!(sql.contains("ORDER BY \"registered_limit\".\"id\" ASC"));
    }
}
