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

use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

mod check;
mod grant;
mod list;
mod revoke;

#[derive(Builder, Clone, Debug)]
#[builder(setter(strip_option, into))]
pub struct SystemUserRoleGrantCheck<'a> {
    user_id: Cow<'a, str>,
    role_id: Cow<'a, str>,
}

impl RestEndpoint for SystemUserRoleGrantCheck<'_> {
    fn method(&self) -> http::Method {
        http::Method::HEAD
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("system/users/{}/roles/{}", self.user_id, self.role_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Builder, Clone, Debug)]
#[builder(setter(strip_option, into))]
pub struct SystemUserRoleGrantSet<'a> {
    user_id: Cow<'a, str>,
    role_id: Cow<'a, str>,
}

impl RestEndpoint for SystemUserRoleGrantSet<'_> {
    fn method(&self) -> http::Method {
        http::Method::PUT
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("system/users/{}/roles/{}", self.user_id, self.role_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Builder, Clone, Debug)]
#[builder(setter(strip_option, into))]
pub struct SystemUserRoleRevoke<'a> {
    user_id: Cow<'a, str>,
    role_id: Cow<'a, str>,
}

impl RestEndpoint for SystemUserRoleRevoke<'_> {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("system/users/{}/roles/{}", self.user_id, self.role_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[derive(Builder, Clone, Debug, Default)]
#[builder(setter(strip_option, into))]
pub struct SystemUserRoleList<'a> {
    user_id: Cow<'a, str>,
}

impl RestEndpoint for SystemUserRoleList<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("system/users/{}/roles", self.user_id).into()
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

pub async fn check_grant<U: AsRef<str>, R: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
    role_id: R,
) -> Result<bool> {
    Ok(openstack_sdk::api::ignore(
        SystemUserRoleGrantCheckBuilder::default()
            .user_id(user_id.as_ref())
            .role_id(role_id.as_ref())
            .build()?,
    )
    .query_async(client.as_ref())
    .await
    .is_ok())
}

pub async fn add_system_grant<U: AsRef<str>, R: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
    role_id: R,
) -> Result<()> {
    openstack_sdk::api::ignore(
        SystemUserRoleGrantSetBuilder::default()
            .user_id(user_id.as_ref())
            .role_id(role_id.as_ref())
            .build()?,
    )
    .query_async(client.as_ref())
    .await?;
    Ok(())
}

pub async fn revoke_system_grant<U: AsRef<str>, R: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
    role_id: R,
) -> Result<()> {
    openstack_sdk::api::ignore(
        SystemUserRoleRevokeBuilder::default()
            .user_id(user_id.as_ref())
            .role_id(role_id.as_ref())
            .build()?,
    )
    .query_async(client.as_ref())
    .await?;
    Ok(())
}

pub async fn list_system_roles<U: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    user_id: U,
) -> Result<Vec<openstack_keystone_api_types::v3::role_assignment::Role>> {
    Ok(SystemUserRoleListBuilder::default()
        .user_id(user_id.as_ref())
        .build()?
        .query_async(client.as_ref())
        .await?)
}
