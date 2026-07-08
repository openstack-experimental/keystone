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
//! API Key (SCIM ingress machine identity, ADR 0021) REST endpoint helpers.
//!
//! Only `create` and `revoke` are needed here: `test_api::scim` provisions
//! an API Key purely to obtain a live bearer token to authenticate SCIM
//! ingress requests, not to exercise the admin CRUD surface itself.

use std::borrow::Cow;
use std::sync::Arc;

use chrono::{Duration, Utc};
use eyre::Result;

use openstack_keystone_api_types::v4::api_key::{ApiKeyCreate, ApiKeyCreateResponse};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct ApiKeyCreateApiRequest {
    api_key: ApiKeyCreate,
}

impl RestEndpoint for ApiKeyCreateApiRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "api-keys".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("api_key", serde_json::to_value(&self.api_key)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// Create a new API Key, returning the metadata plus the one-time bearer
/// token (`kscim_...`).
pub async fn create_api_key(
    tc: &Arc<AsyncOpenStack>,
    api_key: ApiKeyCreate,
) -> Result<AsyncResourceGuard<ApiKeyCreateResponse>> {
    let obj: ApiKeyCreateResponse = ApiKeyCreateApiRequest { api_key }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// A key valid for an hour, bound to `provider_id` in `domain_id`.
pub fn sample_api_key_create(domain_id: &str, provider_id: &str) -> ApiKeyCreate {
    ApiKeyCreate {
        allowed_ips: None,
        description: Some("test_api scim provisioning key".to_string()),
        domain_id: domain_id.to_string(),
        expires_at: Utc::now() + Duration::hours(1),
        provider_id: provider_id.to_string(),
    }
}

struct ApiKeyRevokeRequest<'a> {
    client_id: Cow<'a, str>,
    domain_id: Cow<'a, str>,
}

impl RestEndpoint for ApiKeyRevokeRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("api-keys/{}/revoke", self.client_id).into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push("domain_id", self.domain_id.as_ref());
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for ApiKeyCreateResponse {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(ApiKeyRevokeRequest {
            client_id: self.api_key.client_id.clone().into(),
            domain_id: self.api_key.domain_id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
