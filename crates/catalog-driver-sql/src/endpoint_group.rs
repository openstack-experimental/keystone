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

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core_types::catalog::*;

use crate::entity::endpoint_group as db_endpoint_group;

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

impl TryFrom<db_endpoint_group::Model> for EndpointGroup {
    type Error = CatalogProviderError;

    /// Tries to convert a database endpoint group model into a domain endpoint
    /// group.
    ///
    /// # Parameters
    /// - `value`: The database endpoint group model.
    ///
    /// # Returns
    /// A `Result` containing the `EndpointGroup`, or a `CatalogProviderError`.
    fn try_from(value: db_endpoint_group::Model) -> Result<Self, Self::Error> {
        let mut builder = EndpointGroupBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name.clone());
        if let Some(description) = &value.description {
            builder.description(description.clone());
        }

        if value.filters != "{}" {
            match serde_json::from_str::<HashMap<String, Value>>(&value.filters) {
                Ok(val) => {
                    builder.filters(val);
                }
                Err(e) => {
                    error!("failed to deserialize endpoint group filters: {e}");
                }
            }
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<EndpointGroupCreate> for db_endpoint_group::ActiveModel {
    type Error = CatalogProviderError;

    /// Tries to convert endpoint group creation parameters into a database
    /// active model.
    ///
    /// # Parameters
    /// - `value`: The endpoint group creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the `ActiveModel`, or a `CatalogProviderError`.
    fn try_from(value: EndpointGroupCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value
                .id
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string())),
            name: Set(value.name),
            description: Set(value.description),
            filters: Set(serde_json::to_string(&value.filters)?),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::entity::endpoint_group;

    pub fn get_endpoint_group_mock<I: Into<String>>(id: I) -> endpoint_group::Model {
        endpoint_group::Model {
            id: id.into(),
            name: "group".into(),
            description: Some("description".into()),
            filters: r#"{"interface":"public"}"#.into(),
        }
    }
}
