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

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::project::Project;
use openstack_keystone_api_types::v4::project::{ProjectCreate, ProjectCreateBuilder};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;
use crate::resource::domain::create_test_domain;
use crate::resource::*;

/// Create request for v4 project (supports optional client-specified id)
#[derive(Clone, Debug)]
struct ProjectV4CreateRequest {
    project: ProjectCreate,
}

impl RestEndpoint for ProjectV4CreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "projects".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("project", serde_json::to_value(&self.project)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("project".into())
    }

    /// Explicitly targets v4 endpoint
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

pub async fn create_project_v4(
    tc: &Arc<AsyncOpenStack>,
    project: ProjectCreate,
) -> Result<AsyncResourceGuard<Project>> {
    let obj: Project = ProjectV4CreateRequest { project }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}
#[tokio::test]
async fn test_v4_project_create_without_id() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;

    let project = create_project_v4(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;

    assert!(!project.id.is_empty(), "project id should not be empty");
    assert!(project.enabled, "project should be enabled");
    assert_eq!(project.domain_id, domain.id);

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_project_create_with_explicit_id() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;

    let explicit_id = Uuid::new_v4().simple().to_string(); // dashless uuid

    let project = create_project_v4(
        &test_client,
        ProjectCreateBuilder::default()
            .id(explicit_id.clone())
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;

    assert_eq!(
        project.id, explicit_id,
        "project id should match the explicitly provided id"
    );
    assert!(project.enabled, "project should be enabled");
    assert_eq!(project.domain_id, domain.id);

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_project_create_with_invalid_id_rejected() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;

    let invalid_id = "not-a-valid-uuid"; // garbage value

    let result = create_project_v4(
        &test_client,
        ProjectCreateBuilder::default()
            .id(invalid_id.to_string())
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await;

    assert!(
        result.is_err(),
        "server should reject invalid project id format"
    );

    domain.delete().await?;
    Ok(())
}

/// v4 create: dashed uuid must be rejected as bad request
///
/// Even though "550e8400-e29b-41d4-a716-446655440000" is a valid UUID,
/// the v4 API strictly requires dashless format.
/// A dashed uuid must be rejected with a 400 Bad Request.
#[tokio::test]
async fn test_v4_project_create_with_dashed_uuid_rejected() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;

    let dashed_id = Uuid::new_v4().hyphenated().to_string();

    let result = create_project_v4(
        &test_client,
        ProjectCreateBuilder::default()
            .id(dashed_id.clone())
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await;

    assert!(
        result.is_err(),
        "server should reject dashed uuid '{}' as bad request",
        dashed_id
    );

    domain.delete().await?;
    Ok(())
}
