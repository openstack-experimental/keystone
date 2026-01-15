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

use openstack_keystone::api::v3::project::types::{ProjectShort, ProjectShortList};

use crate::common::*;

/// List projects available to the user
pub async fn list_auth_projects(tc: &TestClient) -> Result<Vec<ProjectShort>> {
    Ok(tc
        .client
        .get(tc.base_url.join("v3/auth/projects")?)
        .send()
        .await?
        .json::<ProjectShortList>()
        .await?
        .projects)
}

#[tokio::test]
async fn test_list_user_projects() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;
    let projects = list_auth_projects(&admin_client).await?;
    assert!(!projects.is_empty());
    Ok(())
}
