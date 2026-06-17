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

use crate::entity::endpoint as db_endpoint;

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

impl TryFrom<db_endpoint::Model> for Endpoint {
    type Error = CatalogProviderError;

    /// Tries to convert a database endpoint model into a domain endpoint.
    ///
    /// # Parameters
    /// - `value`: The database endpoint model.
    ///
    /// # Returns
    /// A `Result` containing the `Endpoint`, or a `CatalogProviderError`.
    fn try_from(value: db_endpoint::Model) -> Result<Self, Self::Error> {
        let mut builder = EndpointBuilder::default();
        builder.id(value.id);
        builder.interface(value.interface);
        builder.service_id(value.service_id);
        builder.url(value.url);
        builder.enabled(value.enabled);
        if let Some(val) = &value.region_id {
            builder.region_id(val);
        }
        if let Some(extra) = &value.extra
            && extra != "{}"
        {
            match serde_json::from_str::<HashMap<String, Value>>(extra) {
                Ok(val) => {
                    builder.extra(val);
                }
                Err(e) => {
                    error!("failed to deserialize endpoint extra: {e}");
                }
            }
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<EndpointCreate> for db_endpoint::ActiveModel {
    type Error = CatalogProviderError;

    /// Tries to convert endpoint creation parameters into a database active
    /// model.
    ///
    /// # Parameters
    /// - `value`: The endpoint creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the `ActiveModel`, or a `CatalogProviderError`.
    fn try_from(value: EndpointCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value
                .id
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string())),
            legacy_endpoint_id: Set(None),
            interface: Set(value.interface),
            service_id: Set(value.service_id),
            url: Set(value.url),
            extra: Set(Some(serde_json::to_string(&value.extra)?)),
            enabled: Set(value.enabled),
            region_id: Set(value.region_id),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::entity::endpoint;

    pub fn get_endpoint_mock<I: Into<String>>(id: I) -> endpoint::Model {
        endpoint::Model {
            enabled: true,
            extra: None,
            id: id.into(),
            interface: "public".into(),
            legacy_endpoint_id: None,
            service_id: "srv_id".into(),
            region_id: Some("region".into()),
            url: "http://localhost".into(),
        }
    }
}
