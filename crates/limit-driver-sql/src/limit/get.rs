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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::Limit;

use crate::entity::{limit as db_limit, prelude::Limit as DbLimit};
use crate::limit::hydrate;

/// Get the limit by ID.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Limit>, LimitProviderError> {
    let Some(model) = DbLimit::find()
        .filter(db_limit::Column::Id.eq(id.as_ref()))
        .one(db)
        .await
        .context("fetching limit")?
    else {
        return Ok(None);
    };
    Ok(hydrate(db, vec![model]).await?.pop())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;
    use crate::limit::tests::{limit_mock, registered_mock};

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![limit_mock("1")]])
            .append_query_results([vec![registered_mock()]])
            .into_connection();
        assert_eq!(
            get(&db, "1").await.unwrap().unwrap(),
            Limit {
                description: None,
                domain_id: None,
                id: "1".into(),
                project_id: Some("pid".into()),
                region_id: Some("reg1".into()),
                resource_limit: 5,
                resource_name: "cores".into(),
                service_id: "srv".into(),
            }
        );
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_limit::Model>::new()])
            .into_connection();
        assert!(get(&db, "1").await.unwrap().is_none());
    }
}
