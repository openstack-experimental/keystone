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
use reqwest::Client;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::api::v3::role::types::*;

use crate::common::*;

/// Create role.
pub async fn create_role(client: &Client, role: RoleCreate) -> Result<Role> {
    Ok(client
        .post(build_url("v3/roles"))
        .json(&serde_json::to_value(role)?)
        .send()
        .await?
        .json::<RoleResponse>()
        .await?
        .role)
}

#[tokio::test]
#[traced_test]
async fn test_create() -> Result<()> {
    let client = Client::new();
    let admin_auth = get_admin_auth(&client).await?;
    let auth_client = get_auth_client(admin_auth.1).await?;
    let name = uuid::Uuid::new_v4().to_string();
    let role: Role = create_role(
        &auth_client,
        RoleCreate {
            name: name,
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}
