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
use tracing_test::traced_test;

use openstack_keystone::api::v3::role::types::*;

use crate::common::*;
use crate::role::*;

#[tokio::test]
#[traced_test]
async fn test_create() -> Result<()> {
    let mut test_client = TestClient::default()?;
    test_client.auth_admin().await?;
    let name = uuid::Uuid::new_v4().to_string();
    let _role: Role = create_role(
        &test_client,
        RoleCreate {
            name,
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}
