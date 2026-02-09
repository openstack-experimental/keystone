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

use crate::api::common;
use crate::api::error::KeystoneApiError;
use crate::api::types::ProjectBuilder;
use crate::keystone::ServiceState;
use crate::resource::types::{Domain, Project};

/// Get the ProjectBuilder for the given Project.
pub(super) async fn get_project_info_builder(
    state: &ServiceState,
    project: &Project,
    user_domain: &Domain,
) -> Result<ProjectBuilder, KeystoneApiError> {
    let mut project_response = ProjectBuilder::default();
    project_response.id(project.id.clone());
    project_response.name(project.name.clone());
    if project.domain_id == user_domain.id {
        project_response.domain(user_domain.clone().into());
    } else {
        let project_domain =
            common::get_domain(state, Some(&project.domain_id), None::<&str>).await?;
        project_response.domain(project_domain.clone().into());
    }
    Ok(project_response)
}

#[cfg(test)]
mod tests {}
