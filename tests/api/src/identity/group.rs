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

use openstack_keystone_api_types::v3::group::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

/// Create request for group
#[derive(Clone, Debug)]
struct GroupCreateRequest {
    group: GroupCreate,
}

impl RestEndpoint for GroupCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "groups".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("group", serde_json::to_value(&self.group)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("group".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create group
pub async fn create_group(
    tc: &Arc<AsyncOpenStack>,
    group: GroupCreate,
) -> Result<AsyncResourceGuard<Group>> {
    let obj: Group = GroupCreateRequest { group }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// Get request for a single group
struct GroupShowRequest {
    id: String,
}

impl RestEndpoint for GroupShowRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("groups/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("group".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Get a single group by ID
pub async fn get_group(tc: &Arc<AsyncOpenStack>, id: impl Into<String>) -> Result<Group> {
    Ok(GroupShowRequest { id: id.into() }
        .query_async(tc.as_ref())
        .await?)
}

/// Update request for group
#[derive(Clone, Debug)]
struct GroupUpdateRequest {
    id: String,
    group: GroupUpdate,
}

impl RestEndpoint for GroupUpdateRequest {
    fn method(&self) -> http::Method {
        http::Method::PATCH
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("groups/{id}", id = self.id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("group", serde_json::to_value(&self.group)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("group".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Update a group
pub async fn update_group(
    tc: &Arc<AsyncOpenStack>,
    id: impl Into<String>,
    group: GroupUpdate,
) -> Result<Group> {
    Ok(GroupUpdateRequest {
        id: id.into(),
        group,
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Delete request for group
struct GroupDeleteRequest {
    id: String,
}

impl RestEndpoint for GroupDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("groups/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Delete a group
pub async fn delete_group(tc: &Arc<AsyncOpenStack>, id: impl Into<String>) -> Result<()> {
    Ok(
        openstack_sdk::api::ignore(GroupDeleteRequest { id: id.into() })
            .query_async(tc.as_ref())
            .await?,
    )
}

#[async_trait::async_trait]
impl DeletableResource for Group {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(GroupDeleteRequest {
            id: self.id.clone(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
