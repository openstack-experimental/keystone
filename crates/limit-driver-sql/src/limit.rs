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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::limit::LimitProviderError;
use openstack_keystone_core_types::limit::Limit;

use crate::entity::{
    limit as db_limit, prelude::RegisteredLimit as DbRegisteredLimit,
    registered_limit as db_registered_limit,
};

mod create;
mod delete;
mod delete_by_domain;
mod delete_by_project;
mod get;
mod list;
mod update;

pub use create::create;
pub use delete::delete;
pub use delete_by_domain::delete_by_domain;
pub use delete_by_project::delete_by_project;
pub use get::get;
pub use list::list;
pub use update::update;

/// Attach the registered limit information to the limits.
pub(super) async fn hydrate<C: ConnectionTrait>(
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

/// Combine the limit with the registered limit it refers to.
pub(super) fn to_limit(value: db_limit::Model, registered: &db_registered_limit::Model) -> Limit {
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

#[cfg(test)]
pub(super) mod tests {
    use crate::entity::{limit as db_limit, registered_limit as db_registered_limit};

    pub fn limit_mock(id: &str) -> db_limit::Model {
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

    pub fn registered_mock() -> db_registered_limit::Model {
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
}
