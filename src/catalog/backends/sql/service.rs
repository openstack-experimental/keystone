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

use serde_json::Value;
use tracing::error;

use crate::catalog::backends::error::CatalogDatabaseError;
use crate::catalog::types::*;
use crate::db::entity::service as db_service;

mod get;
mod list;

pub use get::get;
pub use list::list;

impl TryFrom<db_service::Model> for Service {
    type Error = CatalogDatabaseError;

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
            match serde_json::from_str::<Value>(extra) {
                Ok(val) => {
                    if let Some(name) = val.get("name").and_then(|x| x.as_str()) {
                        builder.name(name);
                    }
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

#[cfg(test)]
mod tests {
    use crate::db::entity::service;

    pub(super) fn get_service_mock(id: String) -> service::Model {
        service::Model {
            id: id.clone(),
            r#type: Some("type".into()),
            enabled: true,
            extra: Some(r#"{"name": "srv"}"#.to_string()),
        }
    }
}
