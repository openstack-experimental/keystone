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

use openstack_sdk::api::rest_endpoint_prelude::*;

#[derive(Clone, Debug)]
pub struct AuthPluginRevokeAllRequest {
    pub plugin_name: String,
}

impl RestEndpoint for AuthPluginRevokeAllRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("auth_plugins/{}/revoke_all", self.plugin_name).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}
