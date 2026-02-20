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

use eyre::Result;

use openstack_keystone_api_types::v3::user::*;

use crate::common::*;

/// Create user
pub async fn create_user(tc: &TestClient, user: UserCreate) -> Result<User> {
    Ok(tc
        .client
        .post(tc.base_url.join("v3/users")?)
        .json(&serde_json::to_value(UserCreateRequest { user })?)
        .send()
        .await?
        .json::<UserResponse>()
        .await?
        .user)
}
