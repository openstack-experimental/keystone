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
use std::collections::HashMap;

use sea_orm::entity::*;
use serde_json::Value;
use tracing::error;
use uuid::Uuid;

use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::{Domain, DomainBuilder, DomainCreate};

mod create;
mod delete;
mod get;
mod list;

pub use create::create;
pub use delete::delete;
pub use get::{get_domain_by_id, get_domain_by_name, get_domain_enabled};
pub use list::list;

use crate::entity::project as db_project;

pub static NULL_DOMAIN_ID: &str = "<<keystone.domain.root>>";

impl TryFrom<db_project::Model> for Domain {
    type Error = ResourceProviderError;

    fn try_from(value: db_project::Model) -> Result<Self, Self::Error> {
        let mut domain_builder = DomainBuilder::default();
        domain_builder.id(value.id.clone());
        domain_builder.name(value.name.clone());
        if let Some(description) = &value.description {
            domain_builder.description(description.clone());
        }
        domain_builder.enabled(value.enabled.unwrap_or(true));
        if let Some(extra) = &value.extra
            && "{}" != extra
        {
            domain_builder.extra(
                serde_json::from_str::<HashMap<String, Value>>(extra)
                    .inspect_err(|e| error!("failed to deserialize domain extra: {e}"))
                    .unwrap_or_default(),
            );
        }

        Ok(domain_builder.build()?)
    }
}

impl TryFrom<DomainCreate> for db_project::ActiveModel {
    type Error = ResourceProviderError;

    fn try_from(value: DomainCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            description: value.description.map(Set).unwrap_or(NotSet).into(),
            domain_id: Set(NULL_DOMAIN_ID.into()),
            enabled: Set(Some(value.enabled)),
            extra: Set(Some(serde_json::to_string(&value.extra)?)),
            id: Set(value.id.unwrap_or(Uuid::new_v4().simple().to_string())),
            is_domain: Set(true),
            name: Set(value.name),
            parent_id: NotSet,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn get_domain_mock<S: Into<String>>(id: S) -> db_project::Model {
        db_project::Model {
            description: None,
            domain_id: "did".into(),
            enabled: Some(true),
            extra: Some("{}".to_string()),
            id: id.into(),
            is_domain: true,
            name: "name".into(),
            parent_id: None,
        }
    }
}
