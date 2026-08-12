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
//! Dynamic authentication plugin REST endpoint helpers.

use std::{borrow::Cow, sync::Arc};

use eyre::Result;
use openstack_sdk::AsyncOpenStack;
use openstack_sdk::api::QueryAsync;

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

#[derive(Clone, Debug)]
struct AuthPluginIdentityLinkDeleteRequest {
    plugin_name: String,
    external_id: String,
}

impl RestEndpoint for AuthPluginIdentityLinkDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "auth_plugins/{}/identity_links/{}",
            self.plugin_name, self.external_id
        )
        .into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// Delete one external identity link and revoke tokens issued through it.
pub async fn delete_identity_link(
    client: &Arc<AsyncOpenStack>,
    plugin_name: &str,
    external_id: &str,
) -> Result<()> {
    openstack_sdk::api::ignore(AuthPluginIdentityLinkDeleteRequest {
        plugin_name: plugin_name.to_string(),
        external_id: external_id.to_string(),
    })
    .query_async(client.as_ref())
    .await?;
    Ok(())
}
