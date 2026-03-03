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

use openstack_sdk_core::api::rest_endpoint_prelude::*;
use openstack_sdk_core::{AsyncOpenStack, api::QueryAsync};

mod check;
mod grant;

#[derive(Builder, Clone, Debug)]
#[builder(setter(strip_option, into))]
pub struct ProjectUserRoleGrantCheck<'a> {
    project_id: Cow<'a, str>,
    user_id: Cow<'a, str>,
    role_id: Cow<'a, str>,
}

impl RestEndpoint for ProjectUserRoleGrantCheck<'_> {
    fn method(&self) -> http::Method {
        http::Method::HEAD
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "projects/{}/users/{}/roles/{}",
            self.project_id, self.user_id, self.role_id
        )
        .into()
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
pub struct ProjectUserRoleGrantSet<'a> {
    project_id: Cow<'a, str>,
    user_id: Cow<'a, str>,
    role_id: Cow<'a, str>,
}

impl RestEndpoint for ProjectUserRoleGrantSet<'_> {
    fn method(&self) -> http::Method {
        http::Method::PUT
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!(
            "projects/{}/users/{}/roles/{}",
            self.project_id, self.user_id, self.role_id
        )
        .into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

pub async fn check_grant<
    P: AsRef<str> + std::fmt::Display,
    U: AsRef<str> + std::fmt::Display,
    R: AsRef<str> + std::fmt::Display,
>(
    client: &Arc<AsyncOpenStack>,
    project_id: P,
    user_id: U,
    role_id: R,
) -> Result<bool> {
    Ok(openstack_sdk_core::api::ignore(
        ProjectUserRoleGrantCheckBuilder::default()
            .project_id(project_id.as_ref())
            .user_id(user_id.as_ref())
            .role_id(role_id.as_ref())
            .build()?,
    )
    .query_async(client.as_ref())
    .await
    .is_ok())
}

pub async fn add_project_grant<
    P: AsRef<str> + std::fmt::Display,
    U: AsRef<str> + std::fmt::Display,
    R: AsRef<str> + std::fmt::Display,
>(
    client: &Arc<AsyncOpenStack>,
    project_id: P,
    user_id: U,
    role_id: R,
) -> Result<()> {
    openstack_sdk_core::api::ignore(
        ProjectUserRoleGrantSetBuilder::default()
            .project_id(project_id.as_ref())
            .user_id(user_id.as_ref())
            .role_id(role_id.as_ref())
            .build()?,
    )
    .query_async(client.as_ref())
    .await?;
    Ok(())
}
