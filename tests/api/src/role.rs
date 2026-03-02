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

use derive_builder::Builder;
use eyre::Result;

use openstack_keystone_api_types::v3::role::*;
use openstack_sdk_core::api::rest_endpoint_prelude::*;
use openstack_sdk_core::{AsyncOpenStack, api::QueryAsync};

use crate::common::*;
use crate::guard::*;

mod create;
mod list;

#[derive(Builder, Clone, Debug, Default)]
#[builder(setter(strip_option, into))]
struct RoleListRequest {}

impl RestEndpoint for RoleListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "roles".into()
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("roles".into())
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct RoleCreateRequest {
    role: RoleCreate,
}

impl RestEndpoint for RoleCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "roles".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("role", serde_json::to_value(&self.role)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("role".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create role.
pub async fn create_role(tc: &TestClient, role: RoleCreate) -> Result<Role> {
    Ok(tc
        .client
        .post(tc.base_url.join("v3/roles")?)
        .json(&serde_json::to_value(role)?)
        .send()
        .await?
        .json::<RoleResponse>()
        .await?
        .role)
}

/// List roles.
pub async fn list_roles(client: &Arc<AsyncOpenStack>) -> Result<Vec<Role>> {
    Ok(RoleListRequest::default()
        .query_async(client.as_ref())
        .await?)
}

struct RoleDeleteRequest {
    id: String,
}

impl RestEndpoint for RoleDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("roles/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for Role {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk_core::api::ignore(RoleDeleteRequest {
            id: self.id.clone(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
