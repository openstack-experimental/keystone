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
//! v3 user CRUD helpers, generated with [`crate::macros::crud_endpoint`].

use openstack_keystone_api_types::v3::user::*;

use crate::macros::crud_endpoint;

crud_endpoint! {
    create {
        request = UserCreateRequest,
        func = create_user,
        path = "users",
        body_key = "user",
        create_type = UserCreate,
        model = User,
        response_key = "user",
        service = Identity,
        api_version = (3, 0),
    }
    update {
        request = UserUpdateRequest,
        func = update_user,
        path = "users",
        body_key = "user",
        update_type = UserUpdate,
        model = User,
        response_key = "user",
        service = Identity,
        api_version = (3, 0),
    }
    delete_impl {
        request = UserDeleteRequest,
        path = "users",
        model = User,
        service = Identity,
        api_version = (3, 0),
    }
}

/// `GET /v3/users/{user_id}/groups` — a user sub-resource, hand-written.
#[derive(Clone, Debug)]
struct UserGroupsRequest {
    user_id: String,
}

impl ::openstack_sdk::api::rest_endpoint_prelude::RestEndpoint for UserGroupsRequest {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> ::std::borrow::Cow<'static, str> {
        format!("users/{}/groups", self.user_id).into()
    }

    fn service_type(&self) -> ::openstack_sdk::api::rest_endpoint_prelude::ServiceType {
        ::openstack_sdk::api::rest_endpoint_prelude::ServiceType::Identity
    }

    fn response_key(&self) -> Option<::std::borrow::Cow<'static, str>> {
        Some("groups".into())
    }

    fn api_version(&self) -> Option<::openstack_sdk::api::rest_endpoint_prelude::ApiVersion> {
        Some(::openstack_sdk::api::rest_endpoint_prelude::ApiVersion::new(3, 0))
    }
}

/// List the groups `user_id` is a member of.
pub async fn list_user_groups(
    tc: &::std::sync::Arc<::openstack_sdk::AsyncOpenStack>,
    user_id: &str,
) -> ::eyre::Result<Vec<openstack_keystone_api_types::v3::group::Group>> {
    use ::openstack_sdk::api::QueryAsync;
    Ok(UserGroupsRequest {
        user_id: user_id.to_string(),
    }
    .query_async(tc.as_ref())
    .await?)
}
