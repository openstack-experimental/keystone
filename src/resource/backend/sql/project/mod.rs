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
use serde_json::json;
use tracing::error;
use uuid::Uuid;

mod create;
mod get;
mod list;
mod tree;

pub use create::create;
pub use get::get_project;
pub use get::get_project_by_name;
pub use list::list;
pub use tree::get_project_parents;

use crate::db::entity::project as db_project;
use crate::resource::backend::error::ResourceDatabaseError;
use crate::resource::types::{Project, ProjectBuilder, ProjectCreate};

impl TryFrom<db_project::Model> for Project {
    type Error = ResourceDatabaseError;

    fn try_from(value: db_project::Model) -> Result<Self, Self::Error> {
        let mut project_builder = ProjectBuilder::default();
        project_builder.id(value.id.clone());
        project_builder.is_domain(value.is_domain);
        if let Some(parent_id) = &value.parent_id {
            project_builder.parent_id(parent_id);
        }
        project_builder.name(value.name);
        project_builder.domain_id(value.domain_id);
        if let Some(description) = &value.description {
            project_builder.description(description);
        }
        // python keystone defaults to project/domain being enabled when the column is
        // unset.
        project_builder.enabled(value.enabled.unwrap_or(true));
        if let Some(extra) = &value.extra
            && extra != "{}"
        {
            match serde_json::from_str::<Value>(extra) {
                Ok(extras) => {
                    project_builder.extra(extras);
                }
                Err(e) => {
                    error!("failed to deserialize project extra: {e}");
                }
            };
        }

        Ok(project_builder.build()?)
    }
}

impl TryFrom<ProjectCreate> for db_project::ActiveModel {
    type Error = ResourceDatabaseError;

    fn try_from(value: ProjectCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            description: value.description.map(Set).unwrap_or(NotSet).into(),
            domain_id: Set(value.domain_id),
            enabled: Set(Some(value.enabled)),
            extra: Set(Some(serde_json::to_string(
                // For keystone it is important to have at least "{}"
                &value.extra.as_ref().or(Some(&json!({}))),
            )?)),
            id: Set(value.id.unwrap_or(Uuid::new_v4().simple().to_string())),
            is_domain: Set(value.is_domain),
            name: Set(value.name),
            parent_id: value.parent_id.map(Set).unwrap_or(NotSet).into(),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn get_project_mock<S: Into<String>>(id: S) -> db_project::Model {
        db_project::Model {
            description: None,
            domain_id: "did".into(),
            enabled: Some(true),
            extra: Some("{}".to_string()),
            id: id.into(),
            is_domain: false,
            name: "name".into(),
            parent_id: None,
        }
    }
}
