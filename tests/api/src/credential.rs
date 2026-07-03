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
//! Credential REST endpoint helpers and test infrastructure (ADR 0019).

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::v3::credential::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

// ---------------------------------------------------------------------------
// REST Endpoint Implementations
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct CredentialCreateRequest {
    credential: CredentialCreate,
}

impl RestEndpoint for CredentialCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "credentials".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("credential", serde_json::to_value(&self.credential)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("credential".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct CredentialShowRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for CredentialShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("credentials/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("credential".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Default, Clone, Debug)]
pub struct CredentialListRequest {
    pub r#type: Option<String>,
    pub user_id: Option<String>,
}

impl RestEndpoint for CredentialListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "credentials".to_string().into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push_opt("type", self.r#type.as_ref());
        params.push_opt("user_id", self.user_id.as_ref());
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("credentials".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct CredentialUpdateRequest<'a> {
    id: Cow<'a, str>,
    credential: CredentialUpdate,
}

impl RestEndpoint for CredentialUpdateRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::PATCH
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("credentials/{id}", id = self.id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("credential", serde_json::to_value(&self.credential)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("credential".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct CredentialDeleteRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for CredentialDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("credentials/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Create a credential.
pub async fn create_credential(
    tc: &Arc<AsyncOpenStack>,
    credential: CredentialCreate,
) -> Result<AsyncResourceGuard<Credential>> {
    let obj: Credential = CredentialCreateRequest { credential }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// Get a credential by ID.
pub async fn show_credential<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<Credential> {
    Ok(CredentialShowRequest {
        id: id.as_ref().into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// List credentials, optionally filtered by type/user_id.
pub async fn list_credentials(
    tc: &Arc<AsyncOpenStack>,
    r#type: Option<&str>,
    user_id: Option<&str>,
) -> Result<Vec<Credential>> {
    Ok(CredentialListRequest {
        r#type: r#type.map(str::to_string),
        user_id: user_id.map(str::to_string),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Update a credential.
pub async fn update_credential<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    id: I,
    credential: CredentialUpdate,
) -> Result<Credential> {
    Ok(CredentialUpdateRequest {
        id: id.as_ref().into(),
        credential,
    }
    .query_async(tc.as_ref())
    .await?)
}

#[async_trait::async_trait]
impl DeletableResource for Credential {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(CredentialDeleteRequest {
            id: self.id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
