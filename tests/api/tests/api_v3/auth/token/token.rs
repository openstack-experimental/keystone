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

use std::{collections::HashMap, sync::Arc};

//use openstack_keystone_api_types::scope::*;
use eyre::Result;
use openstack_keystone_api_types::v3::{project::ProjectCreateBuilder, user::UserCreateBuilder};
use openstack_sdk::{
    AsyncOpenStack,
    auth::authtoken::AuthTokenScope,
    config::CloudConfig,
    types::identity::v3::{Domain as SdkDomain, Project as SdkProject},
};
use uuid::Uuid;

use test_api::assignment::grant::add_project_grant;
use test_api::auth::project::list_auth_projects;
use test_api::common::get_session_by_user_password;
use test_api::guard::ResourceGuard;
use test_api::identity::user::create_user;
use test_api::resource::project::create_project;
use test_api::role::list_roles;

#[tokio::test]
async fn test_rescope_project_scope() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let password = "TestPassword123!";

    let user = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id("default")
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    let project_a = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(format!("src_{}", Uuid::new_v4().simple()))
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let project_b = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(format!("dst_{}", Uuid::new_v4().simple()))
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&admin)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member = roles.get("member").expect("member role must exist");

    add_project_grant(&admin, &project_a.id, &user.id, member).await?;
    add_project_grant(&admin, &project_b.id, &user.id, member).await?;

    let base_user_sdk = get_session_by_user_password(&user.name, &user.domain_id, password).await?;
    let projects = list_auth_projects(&base_user_sdk).await?;
    assert!(projects.iter().any(|p| p.id == project_b.id));

    let mut user_sdk_by_id = base_user_sdk.as_ref().clone();
    user_sdk_by_id
        .authorize(Some(project_scope_id(&project_a.id)), false, false)
        .await?;
    user_sdk_by_id
        .authorize(Some(project_scope_id(&project_b.id)), false, false)
        .await?;
    assert_current_project(&user_sdk_by_id, &project_b.id);

    let mut user_sdk_by_name = base_user_sdk.as_ref().clone();
    user_sdk_by_name
        .authorize(Some(project_scope_id(&project_a.id)), false, false)
        .await?;
    user_sdk_by_name
        .authorize(
            Some(project_scope_name(&project_b.name, &project_b.domain_id)),
            false,
            false,
        )
        .await?;
    assert_current_project(&user_sdk_by_name, &project_b.id);

    user.delete().await?;
    project_a.delete().await?;
    project_b.delete().await?;
    Ok(())
}

fn project_scope_id(project_id: &str) -> AuthTokenScope {
    AuthTokenScope::Project(SdkProject {
        id: Some(project_id.to_string()),
        name: None,
        domain: None,
    })
}

fn project_scope_name(name: &str, domain_id: &str) -> AuthTokenScope {
    AuthTokenScope::Project(SdkProject {
        id: None,
        name: Some(name.to_string()),
        domain: Some(SdkDomain {
            id: Some(domain_id.to_string()),
            name: None,
        }),
    })
}

fn assert_current_project(client: &AsyncOpenStack, project_id: &str) {
    let current_project_id = client
        .get_auth_info()
        .and_then(|auth| auth.token.project)
        .and_then(|project| project.id)
        .expect("token should be scoped to a project");

    assert_eq!(project_id, current_project_id.as_str());
}
