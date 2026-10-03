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
use openstack_keystone_core_types::limit::{RegisteredLimit, RegisteredLimitUpdate};

use crate::entity::{
    prelude::RegisteredLimit as DbRegisteredLimit, registered_limit as db_registered_limit,
};
use crate::registered_limit::{ensure_not_referenced, ensure_unique};

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
