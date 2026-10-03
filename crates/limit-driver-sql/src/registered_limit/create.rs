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
use uuid::Uuid;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::{RegisteredLimit, RegisteredLimitCreate};

use crate::entity::registered_limit as db_registered_limit;
use crate::registered_limit::ensure_unique;

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
