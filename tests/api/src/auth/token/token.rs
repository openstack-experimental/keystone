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

use eyre::Result;

use openstack_keystone_api_types::scope::*;

use crate::auth::project::list_auth_projects;
use crate::common::*;

#[tokio::test]
async fn test_rescope_project_scope() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;

    let projects = list_auth_projects(&admin_client).await?;

    for project in projects {
        // auth with project_id
        admin_client
            .rescope(Some(Scope::Project(ScopeProject {
                id: Some(project.id.clone()),
                ..Default::default()
            })))
            .await?;
        // auth with project name and domain_id
        admin_client
            .rescope(Some(Scope::Project(ScopeProject {
                id: None,
                name: Some(project.name.clone()),
                domain: Some(Domain {
                    id: Some(project.domain_id.clone()),
                    name: None,
                }),
            })))
            .await?;
    }

    Ok(())
}
