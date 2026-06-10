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

use crate::common::{TestClient, get_password_auth};
use crate::guard::ResourceGuard;
use tracing_test::traced_test;

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
#[traced_test]
async fn test_auth_projects_empty_for_user_without_roles() -> Result<()> {
    use crate::identity::user::create_user;
    use openstack_keystone_api_types::v3::user::UserCreateBuilder;
    use uuid::Uuid;

    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());
    let password = "TestPassword123!";

    // Create a user with no role assignments
    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    // Authenticate as the user with no scope
    let mut user_client = TestClient::default()?;
    user_client
        .auth_password(
            get_password_auth(&guard.name, password, &guard.domain_id)?,
            None,
        )
        .await?;

    // /auth/projects should return empty list since user has no roles
    let rsp = user_client
        .client
        .get(user_client.base_url.join("v3/auth/projects")?)
        .send()
        .await?;

    let body: serde_json::Value = rsp.json().await?;
    let projects = body["projects"].as_array().map(|a| a.len()).unwrap_or(0);

    assert_eq!(
        projects, 0,
        "Expected empty project list for user with no roles, got {}",
        projects
    );

    guard.delete().await?;
    Ok(())
}
