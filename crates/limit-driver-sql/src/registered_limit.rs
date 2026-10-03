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
//! # Registered limits

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

impl From<db_registered_limit::Model> for RegisteredLimit {
    fn from(value: db_registered_limit::Model) -> Self {
        Self {
            default_limit: value.default_limit,
            description: value.description,
            id: value.id,
            region_id: value.region_id,
            resource_name: value.resource_name.unwrap_or_default(),
            service_id: value.service_id.unwrap_or_default(),
        }
    }
}

/// Fail with `Conflict` when another registered limit with the same service,
/// resource name and region exists.
async fn ensure_unique<C: ConnectionTrait>(
    db: &C,
    service_id: &str,
    resource_name: &str,
    region_id: Option<&str>,
    exclude_id: Option<&str>,
) -> Result<(), LimitProviderError> {
    let mut select = DbRegisteredLimit::find()
        .filter(db_registered_limit::Column::ServiceId.eq(service_id))
        .filter(db_registered_limit::Column::ResourceName.eq(resource_name))
        .filter(nullable_eq(
            db_registered_limit::Column::RegionId,
            region_id,
        ));
    if let Some(exclude_id) = exclude_id {
        select = select.filter(db_registered_limit::Column::Id.ne(exclude_id));
    }
    if select
        .one(db)
        .await
        .context("checking registered limit uniqueness")?
        .is_some()
    {
        return Err(LimitProviderError::Conflict(format!(
            "registered limit for service {service_id}, resource {resource_name} and region {region_id:?} already exists"
        )));
    }
    Ok(())
}

/// Fail with `RegisteredLimitInUse` when limits refer to the registered limit.
async fn ensure_not_referenced<C: ConnectionTrait>(
    db: &C,
    id: &str,
) -> Result<(), LimitProviderError> {
    if DbLimit::find()
        .filter(db_limit::Column::RegisteredLimitId.eq(id))
        .count(db)
        .await
        .context("checking registered limit references")?
        > 0
    {
        return Err(LimitProviderError::RegisteredLimitInUse(id.to_string()));
    }
    Ok(())
}

/// Create registered limits in a single transaction.
pub async fn create(
    db: &DatabaseConnection,
    limits: Vec<RegisteredLimitCreate>,
) -> Result<Vec<RegisteredLimit>, LimitProviderError> {
    let txn = db.begin().await.context("starting transaction")?;
    let mut res = Vec::with_capacity(limits.len());
    for limit in limits {
        ensure_unique(
            &txn,
            &limit.service_id,
            &limit.resource_name,
            limit.region_id.as_deref(),
            None,
        )
        .await?;
        let model = db_registered_limit::ActiveModel {
            internal_id: NotSet,
            id: Set(limit
                .id
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string())),
            service_id: Set(Some(limit.service_id)),
            region_id: Set(limit.region_id),
            resource_name: Set(Some(limit.resource_name)),
            default_limit: Set(limit.default_limit),
            description: Set(limit.description),
        }
        .insert(&txn)
        .await
        .context("creating registered limit")?;
        res.push(model.into());
    }
    txn.commit().await.context("committing transaction")?;
    Ok(res)
}

/// Get the registered limit by ID.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<RegisteredLimit>, LimitProviderError> {
    Ok(DbRegisteredLimit::find()
        .filter(db_registered_limit::Column::Id.eq(id.as_ref()))
        .one(db)
        .await
        .context("fetching registered limit")?
        .map(Into::into))
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

/// Update the registered limit.
///
/// A registered limit referenced by limits can not be changed.
pub async fn update<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
    data: RegisteredLimitUpdate,
) -> Result<RegisteredLimit, LimitProviderError> {
    let id = id.as_ref();
    let txn = db.begin().await.context("starting transaction")?;
    let existing = DbRegisteredLimit::find()
        .filter(db_registered_limit::Column::Id.eq(id))
        .one(&txn)
        .await
        .context("fetching registered limit for update")?
        .ok_or_else(|| LimitProviderError::RegisteredLimitNotFound(id.to_string()))?;
    ensure_not_referenced(&txn, id).await?;

    let service_id = data
        .service_id
        .clone()
        .or_else(|| existing.service_id.clone())
        .unwrap_or_default();
    let resource_name = data
        .resource_name
        .clone()
        .or_else(|| existing.resource_name.clone())
        .unwrap_or_default();
    let region_id = match &data.region_id {
        Some(region_id) => region_id.clone(),
        None => existing.region_id.clone(),
    };
    if service_id != existing.service_id.clone().unwrap_or_default()
        || resource_name != existing.resource_name.clone().unwrap_or_default()
        || region_id != existing.region_id
    {
        ensure_unique(
            &txn,
            &service_id,
            &resource_name,
            region_id.as_deref(),
            Some(id),
        )
        .await?;
    }

    let mut active: db_registered_limit::ActiveModel = existing.into();
    active.service_id = Set(Some(service_id));
    active.resource_name = Set(Some(resource_name));
    active.region_id = Set(region_id);
    if let Some(default_limit) = data.default_limit {
        active.default_limit = Set(default_limit);
    }
    if let Some(description) = data.description {
        active.description = Set(description);
    }
    let model = active
        .update(&txn)
        .await
        .context("updating registered limit")?;
    txn.commit().await.context("committing transaction")?;
    Ok(model.into())
}

/// Delete the registered limit.
///
/// A registered limit referenced by limits can not be deleted.
pub async fn delete<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<(), LimitProviderError> {
    let id = id.as_ref();
    let txn = db.begin().await.context("starting transaction")?;
    ensure_not_referenced(&txn, id).await?;
    let res = DbRegisteredLimit::delete_many()
        .filter(db_registered_limit::Column::Id.eq(id))
        .exec(&txn)
        .await
        .context("deleting registered limit")?;
    if res.rows_affected == 0 {
        return Err(LimitProviderError::RegisteredLimitNotFound(id.to_string()));
    }
    txn.commit().await.context("committing transaction")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;

    pub(crate) fn get_mock(id: &str) -> db_registered_limit::Model {
        db_registered_limit::Model {
            internal_id: 1,
            id: id.into(),
            service_id: Some("srv".into()),
            region_id: None,
            resource_name: Some("cores".into()),
            default_limit: 10,
            description: Some("descr".into()),
        }
    }

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("1")]])
            .into_connection();
        assert_eq!(
            get(&db, "1").await.unwrap().unwrap(),
            RegisteredLimit {
                default_limit: 10,
                description: Some("descr".into()),
                id: "1".into(),
                region_id: None,
                resource_name: "cores".into(),
                service_id: "srv".into(),
            }
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "registered_limit"."internal_id", "registered_limit"."id", "registered_limit"."service_id", "registered_limit"."region_id", "registered_limit"."resource_name", "registered_limit"."default_limit", "registered_limit"."description" FROM "registered_limit" WHERE "registered_limit"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            )]
        );
    }

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
