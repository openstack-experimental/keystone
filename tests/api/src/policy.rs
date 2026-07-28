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
//! Legacy policy document store (`/v3/policies`) test client.
use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::v3::policy::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct PolicyCreateRequestInternal {
    policy: PolicyCreate,
}

impl RestEndpoint for PolicyCreateRequestInternal {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "policies".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("policy", serde_json::to_value(&self.policy)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("policy".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct PolicyShowRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for PolicyShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("policies/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("policy".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Default, Clone, Debug)]
struct PolicyListRequest {
    r#type: Option<String>,
}

impl RestEndpoint for PolicyListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "policies".into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push_opt("type", self.r#type.as_ref());
        params
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("policies".into())
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct PolicyUpdateRequestInternal<'a> {
    id: Cow<'a, str>,
    policy: PolicyUpdate,
}

impl RestEndpoint for PolicyUpdateRequestInternal<'_> {
    fn method(&self) -> http::Method {
        http::Method::PATCH
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("policies/{id}", id = self.id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("policy", serde_json::to_value(&self.policy)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("policy".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct PolicyDeleteRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for PolicyDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("policies/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create a policy.
pub async fn create_policy(
    tc: &Arc<AsyncOpenStack>,
    policy: PolicyCreate,
) -> Result<AsyncResourceGuard<Policy>> {
    let obj: Policy = PolicyCreateRequestInternal { policy }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// Get a policy by ID.
pub async fn show_policy<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<Policy> {
    Ok(PolicyShowRequest {
        id: id.as_ref().into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// List policies.
pub async fn list_policies(tc: &Arc<AsyncOpenStack>) -> Result<Vec<Policy>> {
    Ok(PolicyListRequest::default()
        .query_async(tc.as_ref())
        .await?)
}

/// List policies filtered by blob media type.
pub async fn list_policies_by_type<I: Into<String>>(
    tc: &Arc<AsyncOpenStack>,
    r#type: I,
) -> Result<Vec<Policy>> {
    Ok(PolicyListRequest {
        r#type: Some(r#type.into()),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Update a policy.
pub async fn update_policy<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    id: I,
    policy: PolicyUpdate,
) -> Result<Policy> {
    Ok(PolicyUpdateRequestInternal {
        id: id.as_ref().into(),
        policy,
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Delete a policy.
pub async fn delete_policy<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<()> {
    Ok(openstack_sdk::api::ignore(PolicyDeleteRequest {
        id: id.as_ref().into(),
    })
    .query_async(tc.as_ref())
    .await?)
}

#[async_trait::async_trait]
impl DeletableResource for Policy {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(PolicyDeleteRequest {
            id: self.id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
