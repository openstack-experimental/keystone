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
use openstack_keystone_core_types::limit::{Limit, LimitUpdate};

use crate::entity::{limit as db_limit, prelude::Limit as DbLimit};
use crate::limit::hydrate;

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
