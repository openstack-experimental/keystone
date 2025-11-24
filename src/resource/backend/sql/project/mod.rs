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
mod tree;

pub use get::get_project;
pub use get::get_project_by_name;
pub use tree::get_project_parents;

use crate::db::entity::project as db_project;
use crate::resource::backend::error::ResourceDatabaseError;
use crate::resource::types::Project;
use crate::resource::types::ProjectBuilder;

impl TryFrom<db_project::Model> for Project {
    type Error = ResourceDatabaseError;

    fn try_from(value: db_project::Model) -> Result<Self, Self::Error> {
        let mut project_builder = ProjectBuilder::default();
        project_builder.id(value.id.clone());
        if let Some(parent_id) = &value.parent_id {
            project_builder.parent_id(parent_id);
        }
        project_builder.name(value.name.clone());
        project_builder.domain_id(value.domain_id.clone());
        if let Some(description) = &value.description {
            project_builder.description(description.clone());
        }
        project_builder.enabled(value.enabled.unwrap_or(false));
        if let Some(extra) = &value.extra {
            project_builder.extra(
                serde_json::from_str::<Value>(extra)
                    .inspect_err(|e| {
                        error!(
                            "failed to deserialize project [id: {}] extra properties: {e}",
                            value.id
                        )
                    })
                    .unwrap_or_default(),
            );
        }

        Ok(project_builder.build()?)
    }
}
