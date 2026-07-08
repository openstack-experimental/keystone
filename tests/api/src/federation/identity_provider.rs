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
//! Federation identity provider REST endpoint helpers.
//!
//! Only the surface `test_api::scim_realm` and `test_api::scim` need to
//! provision a realm's required `idp_id` -- create and delete. Full identity
//! provider CRUD is out of scope for the SCIM test suites.

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::federation::{
    IdentityProvider, IdentityProviderCreate, IdentityProviderCreateBuilder,
};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct IdentityProviderCreateApiRequest {
    identity_provider: IdentityProviderCreate,
}

impl RestEndpoint for IdentityProviderCreateApiRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "federation/identity_providers".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push(
            "identity_provider",
            serde_json::to_value(&self.identity_provider)?,
        );
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("identity_provider".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

pub async fn create_identity_provider(
    tc: &Arc<AsyncOpenStack>,
    identity_provider: IdentityProviderCreate,
) -> Result<AsyncResourceGuard<IdentityProvider>> {
    let obj: IdentityProvider = IdentityProviderCreateApiRequest { identity_provider }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// A realm-ready identity provider create payload: SCIM realm creation only
/// validates that `idp_id` resolves, so the OIDC/JWT plumbing fields are
/// left unset.
pub fn sample_identity_provider_create(domain_id: &str, name: &str) -> IdentityProviderCreate {
    IdentityProviderCreateBuilder::default()
        .name(name)
        .domain_id(domain_id)
        .build()
        .expect("valid identity provider create payload")
}

struct IdentityProviderDeleteRequest<'a> {
    idp_id: Cow<'a, str>,
}

impl RestEndpoint for IdentityProviderDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("federation/identity_providers/{}", self.idp_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for IdentityProvider {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(IdentityProviderDeleteRequest {
            idp_id: self.id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
