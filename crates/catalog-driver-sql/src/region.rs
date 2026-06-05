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
use serde_json::Value;
use tracing::error;
use uuid::Uuid;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core_types::catalog::*;

use crate::entity::region as db_region;

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

impl TryFrom<db_region::Model> for Region {
    type Error = CatalogProviderError;

    /// Tries to convert a database region model into a domain region.
    ///
    /// # Parameters
    /// - `value`: The database region model.
    ///
    /// # Returns
    /// A `Result` containing the `Region`, or a `CatalogProviderError`.
    fn try_from(value: db_region::Model) -> Result<Self, Self::Error> {
        let mut builder = RegionBuilder::default();
        builder.id(value.id.clone());
        if !value.description.is_empty() {
            builder.description(value.description.clone());
        }
        if let Some(parent_region_id) = &value.parent_region_id {
            builder.parent_region_id(parent_region_id.clone());
        }

        if let Some(extra) = &value.extra
            && extra != "{}"
        {
            match serde_json::from_str::<Value>(extra) {
                Ok(val) => {
                    builder.extra(val);
                }
                Err(e) => {
                    error!("failed to deserialize region extra: {e}");
                }
            }
        }

        Ok(builder.build()?)
    }
}

impl TryFrom<RegionCreate> for db_region::ActiveModel {
    type Error = CatalogProviderError;

    /// Tries to convert region creation parameters into a database active model.
    ///
    /// # Parameters
    /// - `value`: The region creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the `ActiveModel`, or a `CatalogProviderError`.
    fn try_from(value: RegionCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value
                .id
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string())),
            description: Set(value.description.unwrap_or_default()),
            parent_region_id: Set(value.parent_region_id),
            extra: Set(Some(serde_json::to_string(&value.extra)?)),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::entity::region;

    pub fn get_region_mock<I: Into<String>>(id: I) -> region::Model {
        region::Model {
            id: id.into(),
            description: "region description".into(),
            parent_region_id: None,
            extra: Some(r#"{"key": "value"}"#.to_string()),
        }
    }
}
