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

use openstack_keystone_api_types::v3::user::*;
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct UserCreateRequest {
    user: UserCreate,
}

impl RestEndpoint for UserCreateRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "users".to_string().into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("user", serde_json::to_value(&self.user)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("user".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

/// Create user
pub async fn create_user(
    tc: &Arc<AsyncOpenStack>,
    user: UserCreate,
) -> Result<AsyncResourceGuard<User>> {
    let obj: User = UserCreateRequest { user }.query_async(tc.as_ref()).await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

//impl RestEndpoint for UserListParameters {
//    fn method(&self) -> http::Method {
//        http::Method::GET
//    }
//
//    fn endpoint(&self) -> Cow<'static, str> {
//        "users".to_string().into()
//    }
//
//    fn parameters(&self) -> QueryParams<'_> {
//        let mut params = QueryParams::default();
//        params.push_opt("domain_id", self.domain_id.as_ref());
//        params.push_opt("name", self.name.as_ref());
//        params.push_opt("unique_id", self.unique_id.as_ref());
//
//        params
//    }
//
//    fn service_type(&self) -> ServiceType {
//        ServiceType::Identity
//    }
//
//    fn response_key(&self) -> Option<Cow<'static, str>> {
//        Some("users".into())
//    }
//
//    /// Returns required API version
//    fn api_version(&self) -> Option<ApiVersion> {
//        Some(ApiVersion::new(3, 0))
//    }
//}

struct UserDeleteRequest {
    id: String,
}

impl RestEndpoint for UserDeleteRequest {
    fn method(&self) -> http::Method {
        http::Method::DELETE
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("users/{id}", id = self.id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(3, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for User {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(UserDeleteRequest {
            id: self.id.clone(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}
