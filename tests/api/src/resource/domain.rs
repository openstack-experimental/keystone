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

#[tokio::test]
async fn test_domain_create() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    assert!(!domain.id.is_empty(), "domain id should not be empty");
    assert!(domain.enabled, "domain should be enabled by default");
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_domain_show() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let shown = get_domain(&test_client, &domain.id)
        .await?
        .expect("domain must be found");
    assert_eq!(shown.id, domain.id);
    assert_eq!(shown.name, domain.name);
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_domain_list() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let params = DomainListRequest {
        ids: Some(domain.id.clone()),
        name: None,
    };
    let domains = list_domains(&test_client, params).await?;
    assert!(
        !domains.is_empty(),
        "domain list should contain the created domain"
    );
    assert_eq!(domains[0].id, domain.id);
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_domain_delete() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_domain(
        &test_client,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    delete_domain(&test_client, &domain.id).await?;
    let result = get_domain(&test_client, &domain.id).await;
    assert!(result.is_err(), "domain should be deleted");
    domain.delete().await?;
    Ok(())
}
