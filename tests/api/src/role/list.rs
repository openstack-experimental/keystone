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

use openstack_keystone_api_types::v3::role::Role;

use crate::common::*;
use crate::role::*;

#[tokio::test]
#[traced_test]
async fn test_list() -> Result<()> {
    let mut test_client = TestClient::default()?;
    test_client.auth_admin().await?;
    let _roles: Vec<Role> = list_roles(&test_client).await?;
    Ok(())
}
