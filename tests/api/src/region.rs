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

use openstack_keystone_api_types::v3::region::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct RegionCreateRequestInternal {
    region: RegionCreate,
}

impl RestEndpoint for RegionCreateRequestInternal {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "regions".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("region", serde_json::to_value(&self.region)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("region".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct RegionShowRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for RegionShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("regions/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("region".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Default, Clone, Debug)]
struct RegionListRequest {}

impl RestEndpoint for RegionListRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "regions".into()
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("regions".into())
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Clone, Debug)]
struct RegionUpdateRequestInternal<'a> {
    id: Cow<'a, str>,
    region: RegionUpdate,
}

impl RestEndpoint for RegionUpdateRequestInternal<'_> {
    fn method(&self) -> http::Method {
        http::Method::PATCH
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("regions/{id}", id = self.id).into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("region", serde_json::to_value(&self.region)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("region".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct RegionDeleteRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for RegionDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("regions/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create a region.
pub async fn create_region(
    tc: &Arc<AsyncOpenStack>,
    region: RegionCreate,
) -> Result<AsyncResourceGuard<Region>> {
    let obj: Region = RegionCreateRequestInternal { region }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// Get a region by ID.
pub async fn show_region<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<Region> {
    Ok(RegionShowRequest {
        id: id.as_ref().into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// List regions.
pub async fn list_regions(tc: &Arc<AsyncOpenStack>) -> Result<Vec<Region>> {
    Ok(RegionListRequest::default()
        .query_async(tc.as_ref())
        .await?)
}

/// Update a region.
pub async fn update_region<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    id: I,
    region: RegionUpdate,
) -> Result<Region> {
    Ok(RegionUpdateRequestInternal {
        id: id.as_ref().into(),
        region,
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Delete a region.
pub async fn delete_region<I: AsRef<str>>(tc: &Arc<AsyncOpenStack>, id: I) -> Result<()> {
    Ok(openstack_sdk::api::ignore(RegionDeleteRequest {
        id: id.as_ref().into(),
    })
    .query_async(tc.as_ref())
    .await?)
}

#[async_trait::async_trait]
impl DeletableResource for Region {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(RegionDeleteRequest {
            id: self.id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
