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
