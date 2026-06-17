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

use crate::entity::service as db_service;

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

impl TryFrom<db_service::Model> for Service {
    type Error = CatalogProviderError;

    /// Tries to convert a database service model into a domain service.
    ///
    /// # Parameters
    /// - `value`: The database service model.
    ///
    /// # Returns
    /// A `Result` containing the `Service`, or a `CatalogProviderError`.
    fn try_from(value: db_service::Model) -> Result<Self, Self::Error> {
        let mut builder = ServiceBuilder::default();
        builder.id(value.id.clone());
        if let Some(typ) = &value.r#type {
            builder.r#type(typ);
        }
        builder.enabled(value.enabled);

        if let Some(extra) = &value.extra
            && extra != "{}"
        {
            match serde_json::from_str::<HashMap<String, Value>>(extra) {
                Ok(val) => {
                    builder.extra(val);
                }
                Err(e) => {
                    error!("failed to deserialize service extra: {e}");
                }
            }
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<ServiceCreate> for db_service::ActiveModel {
    type Error = CatalogProviderError;

    /// Tries to convert service creation parameters into a database active
    /// model.
    ///
    /// # Parameters
    /// - `value`: The service creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the `ActiveModel`, or a `CatalogProviderError`.
    fn try_from(value: ServiceCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value
                .id
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string())),
            r#type: Set(value.r#type),
            enabled: Set(value.enabled),
            extra: Set(Some(serde_json::to_string(&value.extra)?)),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::entity::service;

    pub fn get_service_mock<I: Into<String>>(id: I) -> service::Model {
        service::Model {
            id: id.into(),
            r#type: Some("type".into()),
            enabled: true,
            extra: Some(r#"{"name": "srv"}"#.to_string()),
        }
    }
}
