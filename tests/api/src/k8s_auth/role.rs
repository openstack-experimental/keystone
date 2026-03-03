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

use openstack_keystone_api_types::k8s_auth::role::*;
use openstack_sdk_core::api::rest_endpoint_prelude::*;
use openstack_sdk_core::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Builder)]
//#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
struct K8sAuthRoleCreateRequest<'a> {
    /// K8s auth role object.
    role: K8sAuthRoleCreate,
    /// Path parameter.
    instance_id: Cow<'a, str>,
}

impl RestEndpoint for K8sAuthRoleCreateRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "k8s_auth/instances/{instance_id}/roles",
            instance_id = self.instance_id
        )
        .into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("role", serde_json::to_value(&self.role)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("role".into())
    }

    /// Returns required API version
    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// Create auth role
pub async fn create_auth_role<I: AsRef<str>>(
    tc: &Arc<AsyncOpenStack>,
    req: K8sAuthRoleCreate,
    auth_instance_id: I,
) -> Result<AsyncResourceGuard<K8sAuthRole>> {
    let obj: K8sAuthRole = K8sAuthRoleCreateRequestBuilder::default()
        .role(req)
        .instance_id(auth_instance_id.as_ref())
        .build()?
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

//impl RestEndpoint for K8sAuthRoleListParameters {
//    fn method(&self) -> http::Method {
//        http::Method::GET
//    }
//
//    fn endpoint(&self) -> Cow<'static, str> {
//        "k8s_auth/roles".to_string().into()
//    }
//
//    fn parameters(&self) -> QueryParams<'_> {
//        let mut params = QueryParams::default();
//        params.push_opt("auth_instance_id", self.auth_instance_id.as_ref());
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

#[derive(Clone)]
struct K8sAuthRoleDeleteRequest<'a> {
    id: Cow<'a, str>,
}

impl RestEndpoint for K8sAuthRoleDeleteRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("k8s_auth/roles/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for K8sAuthRole {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk_core::api::ignore(K8sAuthRoleDeleteRequest {
            id: self.id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
