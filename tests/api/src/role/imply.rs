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

use openstack_keystone_api_types::v3::role::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct ImpliedRoleCreateRequest {
    prior_role_id: String,
    implied_role_id: String,
}

impl RestEndpoint for ImpliedRoleCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::PUT
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "roles/{prior}/implies/{implied}",
            prior = self.prior_role_id,
            implied = self.implied_role_id
        )
        .into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("role_inference".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create a role imply rule.
pub async fn create_implied_role(
    client: &Arc<AsyncOpenStack>,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<RoleImply> {
    Ok(ImpliedRoleCreateRequest {
        prior_role_id: prior_role_id.to_string(),
        implied_role_id: implied_role_id.to_string(),
    }
    .query_async(client.as_ref())
    .await?)
}

#[derive(Clone, Debug)]
struct ImpliedRoleDeleteRequest {
    prior_role_id: String,
    implied_role_id: String,
}

impl RestEndpoint for ImpliedRoleDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "roles/{prior}/implies/{implied}",
            prior = self.prior_role_id,
            implied = self.implied_role_id
        )
        .into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Delete a role imply rule.
pub async fn delete_implied_role(
    client: &Arc<AsyncOpenStack>,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<()> {
    Ok(openstack_sdk::api::ignore(ImpliedRoleDeleteRequest {
        prior_role_id: prior_role_id.to_string(),
        implied_role_id: implied_role_id.to_string(),
    })
    .query_async(client.as_ref())
    .await?)
}

#[async_trait::async_trait]
impl DeletableResource for RoleImply {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        delete_implied_role(state, &self.prior_role.id, &self.implies.id).await
    }
}

#[derive(Clone, Debug)]
struct ImpliedRoleCheckRequest {
    prior_role_id: String,
    implied_role_id: String,
}

impl RestEndpoint for ImpliedRoleCheckRequest {
    fn method(&self) -> http::Method {
        http::Method::HEAD
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "roles/{prior}/implies/{implied}",
            prior = self.prior_role_id,
            implied = self.implied_role_id
        )
        .into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Check if a role imply rule exists.
pub async fn check_implied_role(
    client: &Arc<AsyncOpenStack>,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<bool> {
    let req = ImpliedRoleCheckRequest {
        prior_role_id: prior_role_id.to_string(),
        implied_role_id: implied_role_id.to_string(),
    };

    Ok(openstack_sdk::api::ignore(req)
        .query_async(client.as_ref())
        .await
        .is_ok())
}

#[derive(Clone, Debug)]
struct ImpliedRoleGetRequest {
    prior_role_id: String,
    implied_role_id: String,
}

impl RestEndpoint for ImpliedRoleGetRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "roles/{prior}/implies/{implied}",
            prior = self.prior_role_id,
            implied = self.implied_role_id
        )
        .into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("role_inference".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Get a role imply rule.
pub async fn get_implied_role(
    client: &Arc<AsyncOpenStack>,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<RoleImply> {
    Ok(ImpliedRoleGetRequest {
        prior_role_id: prior_role_id.to_string(),
        implied_role_id: implied_role_id.to_string(),
    }
    .query_async(client.as_ref())
    .await?)
}

#[derive(Clone, Debug)]
struct ImpliedRoleListRequest {
    prior_role_id: String,
}

impl RestEndpoint for ImpliedRoleListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("roles/{id}/implies", id = self.prior_role_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// List role imply rules for a prior role.
pub async fn list_implied_role(
    client: &Arc<AsyncOpenStack>,
    prior_role_id: &str,
) -> Result<RoleInferenceRules> {
    Ok(ImpliedRoleListRequest {
        prior_role_id: prior_role_id.to_string(),
    }
    .query_async(client.as_ref())
    .await?)
}

#[derive(Clone, Debug, Default)]
struct RoleInferencesListRequest {}

impl RestEndpoint for RoleInferencesListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "role_inferences".into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("role_inferences".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// List all role inference rules.
pub async fn list_role_inferences(client: &Arc<AsyncOpenStack>) -> Result<Vec<ImplyGroup>> {
    Ok(RoleInferencesListRequest::default()
        .query_async(client.as_ref())
        .await?)
}
