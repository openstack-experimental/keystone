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

use derive_builder::Builder;
use eyre::Result;

use openstack_keystone_api_types::v4::token_restriction::*;
use openstack_sdk_core::api::rest_endpoint_prelude::*;
use openstack_sdk_core::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Builder, Clone, Debug)]
#[builder(setter(strip_option, into))]
struct TokenRestrictionCreateRequest {
    restriction: TokenRestrictionCreate,
}

impl RestEndpoint for TokenRestrictionCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "tokens/restrictions".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("restriction", serde_json::to_value(&self.restriction)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("restriction".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// Create project
pub async fn create_token_restriction(
    tc: &Arc<AsyncOpenStack>,
    obj: TokenRestrictionCreate,
) -> Result<AsyncResourceGuard<TokenRestriction>> {
    let obj: TokenRestriction = TokenRestrictionCreateRequestBuilder::default()
        .restriction(obj)
        .build()?
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

struct TokenRestrictionDeleteRequest {
    id: String,
}

impl RestEndpoint for TokenRestrictionDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("tokens/restrictions/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for TokenRestriction {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(
            openstack_sdk_core::api::ignore(TokenRestrictionDeleteRequest {
                id: self.id.clone(),
            })
            .query_async(state.as_ref())
            .await?,
        )
    }
}
