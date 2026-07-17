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

use openstack_keystone_api_types::v3::endpoint::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct EndpointCreateRequestInternal {
    endpoint: EndpointCreate,
}

impl RestEndpoint for EndpointCreateRequestInternal {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "endpoints".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("endpoint", serde_json::to_value(&self.endpoint)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("endpoint".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct EndpointShowRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for EndpointShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("endpoints/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("endpoint".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Default, Clone, Debug)]
struct EndpointListRequest {}

impl RestEndpoint for EndpointListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "endpoints".into()
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("endpoints".into())
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct EndpointUpdateRequestInternal<'a> {
    id: Cow<'a, str>,
    endpoint: EndpointUpdate,
}

impl RestEndpoint for EndpointUpdateRequestInternal<'_> {
    fn method(&self) -> http::Method {
        http::Method::PATCH
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("endpoints/{id}", id = self.id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("endpoint", serde_json::to_value(&self.endpoint)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("endpoint".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct EndpointDeleteRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for EndpointDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("endpoints/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create an endpoint.
pub async fn create_endpoint(
    tc: &Arc<AsyncOpenStack>,
    endpoint: EndpointCreate,
) -> Result<AsyncResourceGuard<Endpoint>> {
    let obj: Endpoint = EndpointCreateRequestInternal { endpoint }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// Get an endpoint by ID.
pub async fn show_endpoint<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<Endpoint> {
    Ok(EndpointShowRequest {
        id: id.as_ref().into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// List endpoints.
pub async fn list_endpoints(tc: &Arc<AsyncOpenStack>) -> Result<Vec<Endpoint>> {
    Ok(EndpointListRequest::default()
        .query_async(tc.as_ref())
        .await?)
}

/// Update an endpoint.
pub async fn update_endpoint<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    id: I,
    endpoint: EndpointUpdate,
) -> Result<Endpoint> {
    Ok(EndpointUpdateRequestInternal {
        id: id.as_ref().into(),
        endpoint,
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Delete an endpoint.
pub async fn delete_endpoint<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<()> {
    Ok(openstack_sdk::api::ignore(EndpointDeleteRequest {
        id: id.as_ref().into(),
    })
    .query_async(tc.as_ref())
    .await?)
}

#[async_trait::async_trait]
impl DeletableResource for Endpoint {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(EndpointDeleteRequest {
            id: self.id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
