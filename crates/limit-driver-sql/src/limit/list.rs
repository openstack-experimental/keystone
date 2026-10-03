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
use openstack_keystone_core_types::limit::{Limit, LimitListParameters};

use crate::entity::{
    limit as db_limit,
    prelude::{Limit as DbLimit, RegisteredLimit as DbRegisteredLimit},
    registered_limit as db_registered_limit,
};
use crate::limit::hydrate;

/// List limits.
pub async fn list(
    db: &DatabaseConnection,
    params: &LimitListParameters,
) -> Result<Vec<Limit>, LimitProviderError> {
    // The service, region and resource name are attributes of the registered
    // limit.
    let registered_ids = if params.service_id.is_some()
        || params.region_id.is_some()
        || params.resource_name.is_some()
    {
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
        let ids: Vec<String> = select
            .all(db)
            .await
            .context("fetching registered limits for the limits filter")?
            .into_iter()
            .map(|r| r.id)
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Some(ids)
    } else {
        None
    };
    let models = get_list_query(params, registered_ids)
        .all(db)
        .await
        .context("fetching limits")?;
    hydrate(db, models).await
}

/// Prepare the paginated query for listing limits.
///
/// `registered_ids` restricts the limits to the given registered limits.
fn get_list_query(
    params: &LimitListParameters,
    registered_ids: Option<Vec<String>>,
) -> Cursor<SelectModel<db_limit::Model>> {
    let mut select = DbLimit::find();
    if let Some(ids) = registered_ids {
        select = select.filter(db_limit::Column::RegisteredLimitId.is_in(ids));
    }
    if let Some(project_id) = &params.project_id {
        select = select.filter(db_limit::Column::ProjectId.eq(project_id));
    }
    if let Some(project_ids) = &params.project_ids {
        select = select.filter(db_limit::Column::ProjectId.is_in(project_ids));
    }
    if let Some(domain_id) = &params.domain_id {
        select = select.filter(db_limit::Column::DomainId.eq(domain_id));
    }
    let mut cursor = select.cursor_by(db_limit::Column::Id);
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
    use crate::entity::registered_limit as db_registered_limit;
    use crate::limit::tests::{limit_mock, registered_mock};

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![limit_mock("1")]])
            .append_query_results([vec![registered_mock()]])
            .into_connection();
        let res = list(
            &db,
            &LimitListParameters {
                project_id: Some("pid".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(1, res.len());
        let sql = format!("{:?}", db.into_transaction_log()).replace("\\\"", "\"");
        assert!(sql.contains("\"limit\".\"project_id\" = "));
        assert!(sql.contains("ORDER BY \"limit\".\"id\" ASC"));
    }

    #[tokio::test]
    async fn test_list_no_registered_match() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_registered_limit::Model>::new()])
            .into_connection();
        let res = list(
            &db,
            &LimitListParameters {
                service_id: Some("srv".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(res.is_empty());
    }

    #[tokio::test]
    async fn test_list_project_ids() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![limit_mock("1")]])
            .append_query_results([vec![registered_mock()]])
            .into_connection();
        let res = list(
            &db,
            &LimitListParameters {
                project_ids: Some(vec!["p1".into(), "p2".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(1, res.len());
        let sql = format!("{:?}", db.into_transaction_log()).replace("\\\"", "\"");
        assert!(sql.contains("\"limit\".\"project_id\" IN ("));
    }
}
