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

use openstack_keystone_api_types::v3::project::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

/// Create request for project
#[derive(Clone, Debug)]
struct ProjectCreateRequest {
    project: ProjectCreate,
}

impl RestEndpoint for ProjectCreateRequest {
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

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create project (original API for AsyncOpenStack)
pub async fn create_project(
    tc: &Arc<AsyncOpenStack>,
    project: ProjectCreate,
) -> Result<AsyncResourceGuard<Project>> {
    let obj: Project = ProjectCreateRequest { project }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// Create request for a project show
struct ProjectShowRequest {
    id: String,
}

impl RestEndpoint for ProjectShowRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("projects/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("project".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Get a single project by ID
pub async fn get_project(tc: &Arc<AsyncOpenStack>, id: impl Into<String>) -> Result<Project> {
    Ok(ProjectShowRequest { id: id.into() }
        .query_async(tc.as_ref())
        .await?)
}

/// List request for projects
#[derive(Default)]
pub struct ProjectListRequest {
    /// Filter projects by domain ID.
    pub domain_id: Option<String>,

    /// Filter projects by the `id` attribute.
    pub ids: Option<String>,

    /// Filter projects by name.
    pub name: Option<String>,
}

impl RestEndpoint for ProjectListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "projects".to_string().into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push_opt("domain_id", self.domain_id.as_ref());
        params.push_opt("ids", self.ids.as_ref());
        params.push_opt("name", self.name.as_ref());
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("projects".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// List projects
pub async fn list_projects(
    tc: &Arc<AsyncOpenStack>,
    params: ProjectListRequest,
) -> Result<Vec<ProjectShort>> {
    Ok(params.query_async(tc.as_ref()).await?)
}

/// Delete request for project
struct ProjectDeleteRequest {
    id: String,
}

impl RestEndpoint for ProjectDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("projects/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Delete a project
pub async fn delete_project(tc: &Arc<AsyncOpenStack>, id: impl Into<String>) -> Result<()> {
    Ok(
        openstack_sdk::api::ignore(ProjectDeleteRequest { id: id.into() })
            .query_async(tc.as_ref())
            .await?,
    )
}
#[async_trait::async_trait]
impl DeletableResource for Project {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(ProjectDeleteRequest {
            id: self.id.clone(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
