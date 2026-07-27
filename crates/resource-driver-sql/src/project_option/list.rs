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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::ProjectOptions;

use crate::entity::{prelude::ProjectOption as DbProjectOption, project_option};

/// List options of a project (or domain) by its ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The project (or domain) ID.
///
/// # Returns
/// A `Result` containing `ProjectOptions` if successful, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn list_by_project_id<C, S>(
    db: &C,
    project_id: S,
) -> Result<ProjectOptions, ResourceProviderError>
where
    C: ConnectionTrait,
    S: AsRef<str>,
{
    Ok(ProjectOptions::from_iter(
        DbProjectOption::find()
            .filter(project_option::Column::ProjectId.eq(project_id.as_ref()))
            .all(db)
            .await
            .context("fetching options of the project")?,
    ))
}
