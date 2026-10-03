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
//! # Limits

use std::collections::{HashMap, HashSet};

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{Cursor, SelectModel};
use uuid::Uuid;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::*;

use crate::entity::{
    limit as db_limit,
    prelude::{Limit as DbLimit, RegisteredLimit as DbRegisteredLimit},
    registered_limit as db_registered_limit,
};
use crate::nullable_eq;

/// Combine the limit with the registered limit it refers to.
fn to_limit(value: db_limit::Model, registered: &db_registered_limit::Model) -> Limit {
    Limit {
        description: value.description,
        domain_id: value.domain_id,
        id: value.id,
        project_id: value.project_id,
        region_id: registered.region_id.clone(),
        resource_limit: value.resource_limit,
        resource_name: registered.resource_name.clone().unwrap_or_default(),
        service_id: registered.service_id.clone().unwrap_or_default(),
    }
}

/// Attach the registered limit information to the limits.
async fn hydrate<C: ConnectionTrait>(
    db: &C,
    models: Vec<db_limit::Model>,
) -> Result<Vec<Limit>, LimitProviderError> {
    let ids: HashSet<String> = models
        .iter()
        .filter_map(|m| m.registered_limit_id.clone())
        .collect();
    let registered: HashMap<String, db_registered_limit::Model> = if ids.is_empty() {
        HashMap::new()
    } else {
        DbRegisteredLimit::find()
            .filter(db_registered_limit::Column::Id.is_in(ids))
            .all(db)
            .await
            .context("fetching registered limits of the limits")?
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect()
    };
    models
        .into_iter()
        .map(|m| {
            let reg = m
                .registered_limit_id
                .as_ref()
                .and_then(|id| registered.get(id))
                .ok_or_else(|| {
                    LimitProviderError::Driver(format!(
                        "limit {} refers to a missing registered limit",
                        m.id
                    ))
                })?;
            Ok(to_limit(m.clone(), reg))
        })
        .collect()
}

/// Create limits in a single transaction.
pub async fn create(
    db: &DatabaseConnection,
    limits: Vec<LimitCreate>,
) -> Result<Vec<Limit>, LimitProviderError> {
    let txn = db.begin().await.context("starting transaction")?;
    let mut res = Vec::with_capacity(limits.len());
    for limit in limits {
        let registered = DbRegisteredLimit::find()
            .filter(db_registered_limit::Column::ServiceId.eq(limit.service_id.as_str()))
            .filter(db_registered_limit::Column::ResourceName.eq(limit.resource_name.as_str()))
            .filter(nullable_eq(
                db_registered_limit::Column::RegionId,
                limit.region_id.as_deref(),
            ))
            .one(&txn)
            .await
            .context("fetching the registered limit of the limit")?
            .ok_or_else(|| {
                LimitProviderError::NoLimitReference(format!(
                    "service_id: {}, resource_name: {}, region_id: {:?}",
                    limit.service_id, limit.resource_name, limit.region_id
                ))
            })?;

        let mut dup =
            DbLimit::find().filter(db_limit::Column::RegisteredLimitId.eq(registered.id.as_str()));
        dup = if let Some(project_id) = &limit.project_id {
            dup.filter(db_limit::Column::ProjectId.eq(project_id))
        } else {
            dup.filter(db_limit::Column::DomainId.eq(limit.domain_id.clone()))
        };
        if dup
            .one(&txn)
            .await
            .context("checking limit uniqueness")?
            .is_some()
        {
            return Err(LimitProviderError::Conflict(format!(
                "limit for project {:?} / domain {:?} and registered limit {} already exists",
                limit.project_id, limit.domain_id, registered.id
            )));
        }

        let model = db_limit::ActiveModel {
            internal_id: NotSet,
            id: Set(limit
                .id
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string())),
            project_id: Set(limit.project_id),
            domain_id: Set(limit.domain_id),
            resource_limit: Set(limit.resource_limit),
            description: Set(limit.description),
            registered_limit_id: Set(Some(registered.id.clone())),
        }
        .insert(&txn)
        .await
        .context("creating limit")?;
        res.push(to_limit(model, &registered));
    }
    txn.commit().await.context("committing transaction")?;
    Ok(res)
}

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

/// Update the limit.
pub async fn update<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
    data: LimitUpdate,
) -> Result<Limit, LimitProviderError> {
    let id = id.as_ref();
    let txn = db.begin().await.context("starting transaction")?;
    let existing = DbLimit::find()
        .filter(db_limit::Column::Id.eq(id))
        .one(&txn)
        .await
        .context("fetching limit for update")?
        .ok_or_else(|| LimitProviderError::LimitNotFound(id.to_string()))?;
    let mut active: db_limit::ActiveModel = existing.into();
    if let Some(resource_limit) = data.resource_limit {
        active.resource_limit = Set(resource_limit);
    }
    if let Some(description) = data.description {
        active.description = Set(description);
    }
    let model = active.update(&txn).await.context("updating limit")?;
    let res = hydrate(&txn, vec![model])
        .await?
        .pop()
        .ok_or_else(|| LimitProviderError::LimitNotFound(id.to_string()))?;
    txn.commit().await.context("committing transaction")?;
    Ok(res)
}

/// Delete the limit.
pub async fn delete<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<(), LimitProviderError> {
    let res = DbLimit::delete_many()
        .filter(db_limit::Column::Id.eq(id.as_ref()))
        .exec(db)
        .await
        .context("deleting limit")?;
    if res.rows_affected == 0 {
        return Err(LimitProviderError::LimitNotFound(id.as_ref().to_string()));
    }
    Ok(())
}

/// Delete all limits of the project.
pub async fn delete_by_project<I: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: I,
) -> Result<(), LimitProviderError> {
    DbLimit::delete_many()
        .filter(db_limit::Column::ProjectId.eq(project_id.as_ref()))
        .exec(db)
        .await
        .context("deleting limits of the project")?;
    Ok(())
}

/// Delete all limits of the domain.
pub async fn delete_by_domain<I: AsRef<str>>(
    db: &DatabaseConnection,
    domain_id: I,
) -> Result<(), LimitProviderError> {
    DbLimit::delete_many()
        .filter(db_limit::Column::DomainId.eq(domain_id.as_ref()))
        .exec(db)
        .await
        .context("deleting limits of the domain")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;

    fn limit_mock(id: &str) -> db_limit::Model {
        db_limit::Model {
            internal_id: 1,
            id: id.into(),
            project_id: Some("pid".into()),
            domain_id: None,
            resource_limit: 5,
            description: None,
            registered_limit_id: Some("reg".into()),
        }
    }

    fn registered_mock() -> db_registered_limit::Model {
        db_registered_limit::Model {
            internal_id: 1,
            id: "reg".into(),
            service_id: Some("srv".into()),
            region_id: Some("reg1".into()),
            resource_name: Some("cores".into()),
            default_limit: 10,
            description: None,
        }
    }

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
}
