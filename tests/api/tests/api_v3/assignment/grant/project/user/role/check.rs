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

use std::sync::Arc;

use eyre::{OptionExt, Result};
use tracing_test::traced_test;

use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use super::*;
use test_api::role::list_roles;

#[tokio::test]
#[traced_test]
async fn test_check_auth_roles() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let auth_token = test_client
        .get_auth_info()
        .ok_or_eyre("the configured session must be authenticated")?
        .token;
    let admin_role_id = list_roles(&test_client)
        .await?
        .into_iter()
        .find(|role| role.name == "admin")
        .map(|role| role.id)
        .ok_or_eyre("the bootstrap admin role must exist")?;
    let project_id = auth_token
        .project
        .as_ref()
        .ok_or_eyre("the configured token must be project scoped")?
        .id
        .as_ref()
        .ok_or_eyre("the token project must specify an id")?;

    check_grant(
        &test_client,
        project_id,
        &auth_token.user.id,
        &admin_role_id,
    )
    .await?;

    Ok(())
}
