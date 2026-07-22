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

use openstack_keystone_api_types::v3::domain::*;
use openstack_sdk::api::QueryAsync;
use openstack_sdk::api::rest_endpoint_prelude::*;

use crate::guard::*;
use crate::resource::*;

/// Create request for domain
#[derive(Builder)]
#[builder(setter(strip_option, into))]
#[derive(Clone, Debug)]
struct DomainCreateRequest {
    domain: DomainCreate,
}

impl RestEndpoint for DomainCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "domains".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("domain", serde_json::to_value(&self.domain)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("domain".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create domain
pub async fn create_domain(
    tc: &Arc<AsyncOpenStack>,
    domain: DomainCreate,
) -> Result<AsyncResourceGuard<Domain>> {
    let obj: Domain = DomainCreateRequestBuilder::default()
        .domain(domain)
        .build()?
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// Get request for a single domain
struct DomainShowRequest {
    id: String,
}

impl RestEndpoint for DomainShowRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("domains/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("domain".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Get a single domain by ID
pub async fn get_domain(tc: &Arc<AsyncOpenStack>, id: impl Into<String>) -> Result<Option<Domain>> {
    Ok(DomainShowRequest { id: id.into() }
        .query_async(tc.as_ref())
        .await?)
}

/// Update request for domain
#[derive(Builder)]
#[builder(setter(strip_option, into))]
#[derive(Clone, Debug)]
struct DomainUpdateRequestInternal {
    id: String,
    domain: DomainUpdate,
}

impl RestEndpoint for DomainUpdateRequestInternal {
    fn method(&self) -> http::Method {
        http::Method::PATCH
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("domains/{id}", id = self.id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("domain", serde_json::to_value(&self.domain)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("domain".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Update a domain
pub async fn update_domain(
    tc: &Arc<AsyncOpenStack>,
    id: impl Into<String>,
    domain: DomainUpdate,
) -> Result<Domain> {
    Ok(DomainUpdateRequestInternalBuilder::default()
        .id(id)
        .domain(domain)
        .build()?
        .query_async(tc.as_ref())
        .await?)
}

/// List request for domains
#[derive(Default)]
pub struct DomainListRequest {
    /// Filter domains by the `id` attribute.
    pub ids: Option<String>,

    /// Filter domains by the `name` attribute.
    pub name: Option<String>,
}

impl RestEndpoint for DomainListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "domains".to_string().into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push_opt("ids", self.ids.as_ref());
        params.push_opt("name", self.name.as_ref());
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("domains".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// List domains
pub async fn list_domains(
    tc: &Arc<AsyncOpenStack>,
    params: DomainListRequest,
) -> Result<Vec<Domain>> {
    Ok(params.query_async(tc.as_ref()).await?)
}

/// Delete request for domain
struct DomainDeleteRequest {
    id: String,
}

impl RestEndpoint for DomainDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("domains/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for Domain {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(DomainDeleteRequest {
            id: self.id.clone(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}

/// Delete a domain
pub async fn delete_domain(tc: &Arc<AsyncOpenStack>, id: impl Into<String>) -> Result<()> {
    Ok(
        openstack_sdk::api::ignore(DomainDeleteRequest { id: id.into() })
            .query_async(tc.as_ref())
            .await?,
    )
}

pub async fn create_test_domain(tc: &Arc<AsyncOpenStack>) -> Result<AsyncResourceGuard<Domain>> {
    create_domain(
        tc,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await
}
