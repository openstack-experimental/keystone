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
//! Live token rescoping coverage for issue #994.

use std::sync::Arc;

use eyre::{OptionExt, Result};
use uuid::Uuid;

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, System as ScopeSystem};
use openstack_keystone_api_types::v3::auth::token::Token;
use openstack_keystone_api_types::v3::project::ProjectCreateBuilder;
use openstack_sdk::{
    AsyncOpenStack,
    auth::authtoken::AuthTokenScope,
    types::identity::v3::{Domain as SdkDomain, Project as SdkProject},
};

use test_api::asserts::assert_unauthorized;
use test_api::assignment::grant::add_project_grant;
use test_api::auth::token::authenticate_by_token;
use test_api::common::TestClient;
use test_api::fixtures::{ProjectScopedUser, warn_on_cleanup_failure};
use test_api::guard::ResourceGuard;
use test_api::resource::get_system_scope_config;
use test_api::resource::project::create_project;
use test_api::role::list_roles;

#[tokio::test]
async fn test_rescope_between_authorized_projects() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let target = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let project_b = match create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .name(format!("rescope-dst-{}", Uuid::new_v4().simple()))
            .enabled(true)
            .build()?,
    )
    .await
    {
        Ok(project) => project,
        Err(error) => {
            warn_on_cleanup_failure("project-rescope fixture", target.cleanup().await);
            return Err(error);
        }
    };
    let expected_project_id = project_b.id.clone();

    let result: Result<(String, String)> = async {
        let member_role_id = list_roles(&admin)
            .await?
            .into_iter()
            .find(|role| role.name == "member")
            .map(|role| role.id)
            .ok_or_eyre("the bootstrap member role must exist")?;
        add_project_grant(&admin, &project_b.id, &target.user.id, &member_role_id).await?;

        let mut by_id = target.session.as_ref().clone();
        by_id
            .authorize(Some(project_scope_id(&project_b.id)), false, false)
            .await?;
        let project_by_id = current_sdk_project_id(&by_id)?;

        let mut by_name = target.session.as_ref().clone();
        by_name
            .authorize(
                Some(project_scope_name(&project_b.name, &project_b.domain_id)),
                false,
                false,
            )
            .await?;
        let project_by_name = current_sdk_project_id(&by_name)?;
        Ok((project_by_id, project_by_name))
    }
    .await;

    let project_b_cleanup = project_b.delete().await;
    let target_cleanup = target.cleanup().await;
    project_b_cleanup?;
    target_cleanup?;

    let (project_by_id, project_by_name) = result?;
    assert_eq!(project_by_id, expected_project_id);
    assert_eq!(project_by_name, expected_project_id);
    Ok(())
}

#[tokio::test]
async fn test_rescope_project_to_system_preserves_audit_chain() -> Result<()> {
    let mut client = TestClient::default()?;
    client.auth_admin().await?;
    let parent_audit_id = current_token(&client)?
        .audit_ids
        .first()
        .cloned()
        .ok_or_eyre("the project token must have an audit ID")?;

    client
        .rescope(Some(Scope::System(ScopeSystem { all: Some(true) })))
        .await?;
    let token = current_token(&client)?;

    assert!(token.project.is_none());
    assert!(token.domain.is_none());
    assert!(token.system.as_ref().is_some_and(|system| system.all));
    assert!(token.methods.iter().any(|method| method == "password"));
    assert!(token.methods.iter().any(|method| method == "token"));
    assert!(token.audit_ids.iter().any(|id| id == &parent_audit_id));
    Ok(())
}

#[tokio::test]
async fn test_rescope_to_unauthorized_domain_fails_closed() -> Result<()> {
    let mut client = TestClient::default()?;
    client.auth_admin().await?;
    let token = client
        .token
        .as_ref()
        .ok_or_eyre("the project client must be authenticated")?;
    let response = authenticate_by_token(
        &client,
        token,
        Some(Scope::Domain(
            DomainBuilder::default().id("default").build()?,
        )),
    )
    .await?;

    assert_unauthorized(
        response.error_for_status(),
        "a project token without a domain role must not rescope to that domain",
    );
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

fn current_sdk_project_id(client: &AsyncOpenStack) -> Result<String> {
    client
        .get_auth_info()
        .and_then(|auth| auth.token.project)
        .and_then(|project| project.id)
        .ok_or_eyre("the SDK token must be project scoped")
}

fn current_token(client: &TestClient) -> Result<&Token> {
    client
        .auth
        .as_ref()
        .map(|response| &response.token)
        .ok_or_eyre("the test client must be authenticated")
}
