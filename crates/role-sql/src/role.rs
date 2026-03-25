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

use sea_orm::entity::*;
use serde_json::{Value, json};
use tracing::error;
use uuid::Uuid;

use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::{Role, RoleBuilder, RoleCreate, RoleRef};

mod create;
mod delete;
mod get;
mod list;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::list;

use crate::entity::role as db_role;

static NULL_DOMAIN_ID: &str = "<<null>>";

impl TryFrom<db_role::Model> for Role {
    type Error = RoleProviderError;

    fn try_from(value: db_role::Model) -> Result<Self, Self::Error> {
        let mut builder = RoleBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name.clone());
        if value.domain_id != NULL_DOMAIN_ID {
            builder.domain_id(value.domain_id.clone());
        }
        if let Some(description) = &value.description {
            builder.description(description.clone());
        }
        if let Some(extra) = &value.extra {
            builder.extra(
                serde_json::from_str::<Value>(extra)
                    .inspect_err(|e| error!("failed to deserialize role extra: {e}"))
                    .unwrap_or_default(),
            );
        }

        Ok(builder.build()?)
    }
}

impl From<db_role::Model> for RoleRef {
    fn from(value: db_role::Model) -> Self {
        Self {
            id: value.id,
            name: Some(value.name),
            domain_id: if value.domain_id != NULL_DOMAIN_ID {
                Some(value.domain_id)
            } else {
                None
            },
        }
    }
}

impl TryFrom<RoleCreate> for db_role::ActiveModel {
    type Error = RoleProviderError;
    fn try_from(value: RoleCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value
                .id
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string())),
            name: Set(value.name.clone()),
            domain_id: Set(value
                .domain_id
                .unwrap_or_else(|| NULL_DOMAIN_ID.to_string())),
            description: Set(value.description.clone()),
            extra: Set(Some(serde_json::to_string(
                &value.extra.as_ref().or(Some(&json!({}))),
            )?)),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::entity::role;

    pub fn get_role_mock<I: Into<String>, N: Into<String>>(id: I, name: N) -> role::Model {
        role::Model {
            id: id.into(),
            domain_id: "foo_domain".into(),
            name: name.into(),
            extra: None,
            description: None,
        }
    }
}
