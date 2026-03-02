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

use derive_builder::Builder;
use eyre::Result;

use openstack_keystone_api_types::k8s_auth::auth::*;
use openstack_sdk_core::api::rest_endpoint_prelude::*;

#[derive(Builder)]
//#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthenticationRequest<'a> {
    /// K8s auth role object.
    instance_id: Cow<'a, str>,

    auth: K8sAuthRequest,
}

impl RestEndpoint for K8sAuthenticationRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "k8s_auth/instances/{instance_id}/auth",
            instance_id = self.instance_id
        )
        .into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        Ok(Some((
            "application/json",
            serde_json::to_value(&self.auth)?.to_string().into_bytes(),
        )))
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}
