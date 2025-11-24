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

mod get;

pub use get::get_domain_by_id;
pub use get::get_domain_by_name;

use crate::db::entity::project as db_project;
use crate::resource::backend::error::ResourceDatabaseError;
use crate::resource::types::Domain;
use crate::resource::types::DomainBuilder;

impl TryFrom<db_project::Model> for Domain {
    type Error = ResourceDatabaseError;

    fn try_from(value: db_project::Model) -> Result<Self, Self::Error> {
        let mut domain_builder = DomainBuilder::default();
        domain_builder.id(value.id.clone());
        domain_builder.name(value.name.clone());
        if let Some(description) = &value.description {
            domain_builder.description(description.clone());
        }
        domain_builder.enabled(value.enabled.unwrap_or(false));
        if let Some(extra) = &value.extra {
            domain_builder.extra(
                serde_json::from_str::<Value>(extra)
                    .inspect_err(|e| error!("failed to deserialize domain extra: {e}"))
                    .unwrap_or_default(),
            );
        }

        Ok(domain_builder.build()?)
    }
}
