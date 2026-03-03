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

use openstack_keystone_api_types::k8s_auth::instance::*;
use openstack_sdk_core::api::rest_endpoint_prelude::*;
use openstack_sdk_core::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct K8sAuthInstanceCreateRequest {
    /// K8s auth instance object.
    instance: K8sAuthInstanceCreate,
}

impl RestEndpoint for K8sAuthInstanceCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "k8s_auth/instances".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("instance", serde_json::to_value(&self.instance)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("instance".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// Create auth instance
pub async fn create_auth_instance(
    tc: &Arc<AsyncOpenStack>,
    instance: K8sAuthInstanceCreate,
) -> Result<AsyncResourceGuard<K8sAuthInstance>> {
    let obj: K8sAuthInstance = K8sAuthInstanceCreateRequest { instance }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

//impl RestEndpoint for K8sAuthInstanceListParameters {
//    fn method(&self) -> http::Method {
//        http::Method::GET
//    }
//
//    fn endpoint(&self) -> Cow<'static, str> {
//        "k8s_auth/instances".to_string().into()
//    }
//
//    fn parameters(&self) -> QueryParams<'_> {
//        let mut params = QueryParams::default();
//        params.push_opt("domain_id", self.domain_id.as_ref());
//        params.push_opt("name", self.name.as_ref());
//
//        params
//    }
//
//    fn service_type(&self) -> ServiceType {
//        ServiceType::Identity
//    }
//
//    fn response_key(&self) -> Option<Cow<'static, str>> {
//        Some("instances".into())
//    }
//
//    /// Returns required API version
//    fn api_version(&self) -> Option<ApiVersion> {
//        Some(ApiVersion::new(4, 0))
//    }
//}

struct K8sAuthInstanceDeleteRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for K8sAuthInstanceDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("k8s_auth/instances/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}
#[async_trait::async_trait]
impl DeletableResource for K8sAuthInstance {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(
            openstack_sdk_core::api::ignore(K8sAuthInstanceDeleteRequest {
                id: self.id.clone().into(),
            })
            .query_async(state.as_ref())
            .await?,
        )
    }
}
