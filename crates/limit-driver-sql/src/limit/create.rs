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
use openstack_keystone_core_types::limit::{Limit, LimitCreate};

use crate::entity::{
    limit as db_limit,
    prelude::{Limit as DbLimit, RegisteredLimit as DbRegisteredLimit},
    registered_limit as db_registered_limit,
};
use crate::limit::to_limit;
use crate::nullable_eq;

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
