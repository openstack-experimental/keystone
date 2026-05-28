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
//! Test the SPIFFE binding functionality

use std::borrow::Cow;
use std::sync::Arc;

use derive_builder::Builder;
use eyre::Result;
use url::Url;

use openstack_keystone_api_types::v4::spiffe::binding::{
    SpiffeBinding, SpiffeBindingCreate, SpiffeBindingUpdate,
};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

mod binding;

use crate::guard::*;

#[derive(Clone, Debug)]
struct SpiffeBindingDeleteRequest<'a> {
    svid: Cow<'a, str>,
}

impl RestEndpoint for SpiffeBindingDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        let encoded = Url::parse(&format!("/{svid}", svid = self.svid))
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| self.svid.to_string().replace("/", "%2F"));
        format!("spiffe/bindings/{encoded}").into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for SpiffeBinding {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(SpiffeBindingDeleteRequest {
            svid: self.svid.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}

// Need to redefine the list to be able to implement foreign trait on it
#[derive(Default)]
pub struct SpiffeBindingListParameters {
    /// Domain ID to filter bindings.
    pub domain_id: Option<String>,

    /// User ID to filter bindings.
    pub user_id: Option<String>,
}

impl RestEndpoint for SpiffeBindingListParameters {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "spiffe/bindings".to_string().into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push_opt("domain_id", self.domain_id.as_ref());
        params.push_opt("user_id", self.user_id.as_ref());
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("bindings".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// List SPIFFE bindings
pub async fn list_bindings(tc: &Arc<AsyncOpenStack>) -> Result<Vec<SpiffeBinding>> {
    Ok(SpiffeBindingListParameters::default()
        .query_async(tc.as_ref())
        .await?)
}

#[derive(Builder)]
#[builder(setter(strip_option, into))]
struct SpiffeBindingCreateRequestWrapper {
    binding: SpiffeBindingCreate,
}

impl RestEndpoint for SpiffeBindingCreateRequestWrapper {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "spiffe/bindings".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("binding", serde_json::to_value(&self.binding)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("binding".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

pub async fn create_binding(
    tc: &Arc<AsyncOpenStack>,
    binding: SpiffeBindingCreate,
) -> Result<AsyncResourceGuard<SpiffeBinding>> {
    let obj: SpiffeBinding = SpiffeBindingCreateRequestWrapperBuilder::default()
        .binding(binding)
        .build()?
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

#[derive(Clone, Debug)]
struct SpiffeBindingShowRequest<'a> {
    svid: Cow<'a, str>,
}

impl RestEndpoint for SpiffeBindingShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        let encoded = Url::parse(&format!("/{svid}", svid = self.svid))
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| self.svid.to_string().replace("/", "%2F"));
        format!("spiffe/bindings/{encoded}").into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("binding".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

pub async fn show_binding<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    svid: I,
) -> Result<SpiffeBinding> {
    let obj: SpiffeBinding = SpiffeBindingShowRequest {
        svid: svid.as_ref().into(),
    }
    .query_async(tc.as_ref())
    .await?;
    Ok(obj)
}

#[derive(Clone, Debug)]
struct SpiffeBindingUpdateRequestWrapper<'a> {
    svid: Cow<'a, str>,
    binding: SpiffeBindingUpdate,
}

impl RestEndpoint for SpiffeBindingUpdateRequestWrapper<'_> {
    fn method(&self) -> http::Method {
        http::Method::PUT
    }

    fn endpoint(&self) -> Cow<'static, str> {
        let encoded = Url::parse(&format!("/{svid}", svid = self.svid))
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| self.svid.to_string().replace("/", "%2F"));
        format!("spiffe/bindings/{encoded}").into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("binding", serde_json::to_value(&self.binding)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("binding".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

pub async fn update_binding<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    svid: I,
    update_req: SpiffeBindingUpdate,
) -> Result<SpiffeBinding> {
    let obj: SpiffeBinding = SpiffeBindingUpdateRequestWrapper {
        svid: svid.as_ref().into(),
        binding: update_req,
    }
    .query_async(tc.as_ref())
    .await?;
    Ok(obj)
}
