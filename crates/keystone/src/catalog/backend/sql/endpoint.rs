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

use crate::catalog::{
    CatalogProviderError,
    types::{Endpoint, EndpointBuilder},
};
use crate::db::entity::endpoint as db_endpoint;

mod get;
mod list;

pub use get::get;
pub use list::list;

impl TryFrom<db_endpoint::Model> for Endpoint {
    type Error = CatalogProviderError;

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
            match serde_json::from_str::<Value>(extra) {
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

#[cfg(test)]
mod tests {
    use crate::db::entity::endpoint;

    pub(super) fn get_endpoint_mock(id: String) -> endpoint::Model {
        endpoint::Model {
            id: id.clone(),
            interface: "public".into(),
            service_id: "srv_id".into(),
            region_id: Some("region".into()),
            url: "http://localhost".into(),
            enabled: true,
            extra: None,
            ..Default::default()
        }
    }
}
