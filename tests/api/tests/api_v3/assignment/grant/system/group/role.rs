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

use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

mod check;
mod grant;
mod list;
mod revoke;

struct SystemGroupRoleGrantCheck {
    group_id: String,
    role_id: String,
}

impl RestEndpoint for SystemGroupRoleGrantCheck {
    fn method(&self) -> http::Method {
        http::Method::HEAD
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("system/groups/{}/roles/{}", self.group_id, self.role_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct SystemGroupRoleGrantSet {
    group_id: String,
    role_id: String,
}

impl RestEndpoint for SystemGroupRoleGrantSet {
    fn method(&self) -> http::Method {
        http::Method::PUT
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("system/groups/{}/roles/{}", self.group_id, self.role_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct SystemGroupRoleRevoke {
    group_id: String,
    role_id: String,
}

impl RestEndpoint for SystemGroupRoleRevoke {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("system/groups/{}/roles/{}", self.group_id, self.role_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

struct SystemGroupRoleList {
    group_id: String,
}

impl RestEndpoint for SystemGroupRoleList {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("system/groups/{}/roles", self.group_id).into()
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("roles".into())
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

pub async fn check_grant<G: AsRef<str>, R: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    group_id: G,
    role_id: R,
) -> Result<bool> {
    Ok(openstack_sdk::api::ignore(SystemGroupRoleGrantCheck {
        group_id: group_id.as_ref().to_string(),
        role_id: role_id.as_ref().to_string(),
    })
    .query_async(client.as_ref())
    .await
    .is_ok())
}

pub async fn add_system_grant<G: AsRef<str>, R: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    group_id: G,
    role_id: R,
) -> Result<()> {
    openstack_sdk::api::ignore(SystemGroupRoleGrantSet {
        group_id: group_id.as_ref().to_string(),
        role_id: role_id.as_ref().to_string(),
    })
    .query_async(client.as_ref())
    .await?;
    Ok(())
}

pub async fn revoke_system_grant<G: AsRef<str>, R: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    group_id: G,
    role_id: R,
) -> Result<()> {
    openstack_sdk::api::ignore(SystemGroupRoleRevoke {
        group_id: group_id.as_ref().to_string(),
        role_id: role_id.as_ref().to_string(),
    })
    .query_async(client.as_ref())
    .await?;
    Ok(())
}

pub async fn list_system_roles<G: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    group_id: G,
) -> Result<Vec<openstack_keystone_api_types::v3::role_assignment::Role>> {
    Ok(SystemGroupRoleList {
        group_id: group_id.as_ref().to_string(),
    }
    .query_async(client.as_ref())
    .await?)
}
