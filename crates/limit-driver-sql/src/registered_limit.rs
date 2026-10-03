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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::RegisteredLimit;

use crate::entity::{
    limit as db_limit,
    prelude::{Limit as DbLimit, RegisteredLimit as DbRegisteredLimit},
    registered_limit as db_registered_limit,
};
use crate::nullable_eq;

mod create;
mod delete;
mod get;
mod list;
mod update;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::list;
pub use update::update;

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

/// Fail with `RegisteredLimitInUse` when limits refer to the registered limit.
pub(super) async fn ensure_not_referenced<C: ConnectionTrait>(
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

/// Fail with `Conflict` when another registered limit with the same service,
/// resource name and region exists.
pub(super) async fn ensure_unique<C: ConnectionTrait>(
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

#[cfg(test)]
pub(super) mod tests {
    use crate::entity::registered_limit as db_registered_limit;

    pub fn get_mock(id: &str) -> db_registered_limit::Model {
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
}
