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

use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::scope::*;
use openstack_sdk_core::{AsyncOpenStack, config::CloudConfig};

use crate::auth::project::list_auth_projects;

#[tokio::test]
async fn test_rescope_project_scope() -> Result<()> {
    let mut test_client = AsyncOpenStack::new(&CloudConfig::from_env()?).await?;

    let projects = list_auth_projects(&Arc::new(test_client.clone())).await?;

    for project in projects {
        // auth with project_id
        test_client
            .authorize(
                Some(
                    openstack_sdk_core::auth::authtoken::AuthTokenScope::Project(
                        openstack_sdk_core::types::identity::v3::Project {
                            id: Some(project.id.clone()),
                            name: None,
                            domain: None,
                        },
                    ),
                ),
                false,
                false,
            )
            .await?;
        // auth with project name and domain_id
        test_client
            .authorize(
                Some(
                    openstack_sdk_core::auth::authtoken::AuthTokenScope::Project(
                        openstack_sdk_core::types::identity::v3::Project {
                            id: None,
                            name: Some(project.name.clone()),
                            domain: Some(openstack_sdk_core::types::identity::v3::Domain {
                                id: Some(project.domain_id.clone()),
                                name: None,
                            }),
                        },
                    ),
                ),
                false,
                false,
            )
            .await?;
    }

    Ok(())
}
