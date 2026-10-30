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
//! SDK bindings for the `/v3/projects/{project_id}/tags` API and the tag
//! filters of the project list.

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;
use serde_json::json;

use openstack_keystone_api_types::v3::project::{Project, ProjectTags};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

/// One tag-related request, parameterised by method, path, query and body so
/// all the shapes share a single impl.
struct TagRequest {
    method: http::Method,
    endpoint: String,
    query: Vec<(&'static str, String)>,
    tags: Option<Vec<String>>,
}

impl TagRequest {
    fn new(method: http::Method, endpoint: String) -> Self {
        Self {
            method,
            endpoint,
            query: Vec::new(),
            tags: None,
        }
    }
}

impl RestEndpoint for TagRequest {
    fn method(&self) -> http::Method {
        self.method.clone()
    }

    fn endpoint(&self) -> Cow<'static, str> {
        self.endpoint.clone().into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        for (key, value) in &self.query {
            params.push(*key, value);
        }
        params
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        match &self.tags {
            Some(tags) => {
                let mut params = JsonBodyParams::default();
                params.push("tags", json!(tags));
                params.into_body()
            }
            None => Ok(None),
        }
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// `GET /v3/projects/{project_id}/tags`.
pub async fn list_project_tags(
    client: &Arc<AsyncOpenStack>,
    project_id: &str,
) -> Result<Vec<String>> {
    let tags: ProjectTags =
        TagRequest::new(http::Method::GET, format!("projects/{project_id}/tags"))
            .query_async(client.as_ref())
            .await?;
    Ok(tags.tags)
}

/// `PUT /v3/projects/{project_id}/tags` — replace all the tags.
pub async fn replace_project_tags(
    client: &Arc<AsyncOpenStack>,
    project_id: &str,
    tags: Vec<String>,
) -> Result<Vec<String>> {
    let mut request = TagRequest::new(http::Method::PUT, format!("projects/{project_id}/tags"));
    request.tags = Some(tags);
    let tags: ProjectTags = request.query_async(client.as_ref()).await?;
    Ok(tags.tags)
}

/// `DELETE /v3/projects/{project_id}/tags` — remove all the tags.
pub async fn delete_project_tags(client: &Arc<AsyncOpenStack>, project_id: &str) -> Result<()> {
    openstack_sdk::api::ignore(TagRequest::new(
        http::Method::DELETE,
        format!("projects/{project_id}/tags"),
    ))
    .query_async(client.as_ref())
    .await?;
    Ok(())
}

/// `GET /v3/projects/{project_id}/tags/{tag}` — succeeds (204) when the
/// project carries the tag.
pub async fn check_project_tag(
    client: &Arc<AsyncOpenStack>,
    project_id: &str,
    tag: &str,
) -> Result<()> {
    openstack_sdk::api::ignore(TagRequest::new(
        http::Method::GET,
        format!("projects/{project_id}/tags/{tag}"),
    ))
    .query_async(client.as_ref())
    .await?;
    Ok(())
}

/// `PUT /v3/projects/{project_id}/tags/{tag}` — add a single tag.
pub async fn add_project_tag(
    client: &Arc<AsyncOpenStack>,
    project_id: &str,
    tag: &str,
) -> Result<()> {
    openstack_sdk::api::ignore(TagRequest::new(
        http::Method::PUT,
        format!("projects/{project_id}/tags/{tag}"),
    ))
    .query_async(client.as_ref())
    .await?;
    Ok(())
}

/// `DELETE /v3/projects/{project_id}/tags/{tag}` — remove a single tag.
pub async fn delete_project_tag(
    client: &Arc<AsyncOpenStack>,
    project_id: &str,
    tag: &str,
) -> Result<()> {
    openstack_sdk::api::ignore(TagRequest::new(
        http::Method::DELETE,
        format!("projects/{project_id}/tags/{tag}"),
    ))
    .query_async(client.as_ref())
    .await?;
    Ok(())
}

/// Tag filters of `GET /v3/projects`. Every value is a comma-separated list.
#[derive(Clone, Debug, Default)]
pub struct ProjectTagFilters {
    pub domain_id: Option<String>,
    pub tags: Option<String>,
    pub tags_any: Option<String>,
    pub not_tags: Option<String>,
    pub not_tags_any: Option<String>,
}

/// `GET /v3/projects` with the tag filters.
pub async fn list_projects_by_tags(
    client: &Arc<AsyncOpenStack>,
    filters: ProjectTagFilters,
) -> Result<Vec<Project>> {
    let mut request = TagRequest::new(http::Method::GET, "projects".into());
    for (key, value) in [
        ("domain_id", filters.domain_id),
        ("tags", filters.tags),
        ("tags-any", filters.tags_any),
        ("not-tags", filters.not_tags),
        ("not-tags-any", filters.not_tags_any),
    ] {
        if let Some(value) = value {
            request.query.push((key, value));
        }
    }
    let request = ResponseKeyed {
        inner: request,
        key: "projects",
    };
    Ok(request.query_async(client.as_ref()).await?)
}

/// Wrapper selecting the response key of a [`TagRequest`].
struct ResponseKeyed {
    inner: TagRequest,
    key: &'static str,
}

impl RestEndpoint for ResponseKeyed {
    fn method(&self) -> http::Method {
        self.inner.method()
    }

    fn endpoint(&self) -> Cow<'static, str> {
        self.inner.endpoint()
    }

    fn parameters(&self) -> QueryParams<'_> {
        self.inner.parameters()
    }

    fn service_type(&self) -> ServiceType {
        self.inner.service_type()
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some(self.key.into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        self.inner.api_version()
    }
}
