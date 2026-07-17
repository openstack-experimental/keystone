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

use openstack_keystone_api_types::v3::service::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct ServiceCreateRequestInternal {
    service: ServiceCreate,
}

impl RestEndpoint for ServiceCreateRequestInternal {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "services".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("service", serde_json::to_value(&self.service)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("service".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct ServiceShowRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for ServiceShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("services/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("service".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Default, Clone, Debug)]
struct ServiceListRequest {}

impl RestEndpoint for ServiceListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "services".into()
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("services".into())
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct ServiceUpdateRequestInternal<'a> {
    id: Cow<'a, str>,
    service: ServiceUpdate,
}

impl RestEndpoint for ServiceUpdateRequestInternal<'_> {
    fn method(&self) -> http::Method {
        http::Method::PATCH
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("services/{id}", id = self.id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("service", serde_json::to_value(&self.service)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("service".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct ServiceDeleteRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for ServiceDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("services/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create a service.
pub async fn create_service(
    tc: &Arc<AsyncOpenStack>,
    service: ServiceCreate,
) -> Result<AsyncResourceGuard<Service>> {
    let obj: Service = ServiceCreateRequestInternal { service }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// Get a service by ID.
pub async fn show_service<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<Service> {
    Ok(ServiceShowRequest {
        id: id.as_ref().into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// List services.
pub async fn list_services(tc: &Arc<AsyncOpenStack>) -> Result<Vec<Service>> {
    Ok(ServiceListRequest::default()
        .query_async(tc.as_ref())
        .await?)
}

/// Update a service.
pub async fn update_service<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    id: I,
    service: ServiceUpdate,
) -> Result<Service> {
    Ok(ServiceUpdateRequestInternal {
        id: id.as_ref().into(),
        service,
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Delete a service.
pub async fn delete_service<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<()> {
    Ok(openstack_sdk::api::ignore(ServiceDeleteRequest {
        id: id.as_ref().into(),
    })
    .query_async(tc.as_ref())
    .await?)
}

#[async_trait::async_trait]
impl DeletableResource for Service {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(ServiceDeleteRequest {
            id: self.id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
