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

use openstack_keystone_api_types::v3::project::ProjectShort;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync, config::CloudConfig};

#[derive(Clone, Debug)]
struct AuthProjectsRequest {}

impl RestEndpoint for AuthProjectsRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "auth/projects".to_string().into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("projects".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// List projects available to the user
pub async fn list_auth_projects(client: &Arc<AsyncOpenStack>) -> Result<Vec<ProjectShort>> {
    Ok(AuthProjectsRequest {}.query_async(client.as_ref()).await?)
}

#[tokio::test]
async fn test_list_user_projects() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let projects = list_auth_projects(&test_client).await?;
    assert!(!projects.is_empty());
    Ok(())
}


#[tokio::test]
async fn test_auth_projects_returns_empty_for_user_without_roles() -> Result<()> {
    // Regression test for issue #515:
    // When a user has no role assignments, /auth/projects should return
    // an empty list, not all projects in the system.
    
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;

    // Create a domain for the test user
    let domain_response = admin_client
        .client
        .post(admin_client.base_url.join("v3/domains")?)
        .json(&serde_json::json!({
            "domain": {
                "name": format!("test-domain-{}", uuid::Uuid::new_v4()),
                "enabled": true
            }
        }))
        .send()
        .await?;
    
    let domain: serde_json::Value = domain_response.json().await?;
    let domain_id = domain["domain"]["id"].as_str().unwrap();

    // Create a user with no role assignments
    let user_password = "TestPassword123!";
    let user_response = admin_client
        .client
        .post(admin_client.base_url.join("v3/users")?)
        .json(&serde_json::json!({
            "user": {
                "name": format!("test-user-{}", uuid::Uuid::new_v4()),
                "domain_id": domain_id,
                "password": user_password,
                "enabled": true
            }
        }))
        .send()
        .await?;

    let user: serde_json::Value = user_response.json().await?;
    let user_id = user["user"]["id"].as_str().unwrap();

    // Authenticate as the user with no roles
    let mut user_client = TestClient::default()?;
    user_client
        .auth_password(
            PasswordAuthBuilder::default()
                .user(
                    UserBuilder::default()
                        .id(user_id)
                        .domain(
                            DomainBuilder::default()
                                .id(domain_id)
                                .build()?
                        )
                        .build()?
                )
                .password(user_password)
                .build()?,
            None, // No scope - unscoped auth
        )
        .await?;

    // Call /auth/projects - should return empty list
    let projects = list_auth_projects(&Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?
    ))
    .await?;

    // The user has no role assignments, so projects list should be empty
    assert!(
        projects.is_empty(),
        "User with no role assignments should see no projects. \
        This may indicate the bug from issue #515 is present (returning all projects instead of empty list)"
    );

    Ok(())
}