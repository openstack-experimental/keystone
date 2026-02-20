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
use std::env;

use openstack_keystone_api_types::scope::*;
use openstack_keystone_api_types::v3::auth::token::IdentityBuilder;

use crate::common::*;

#[tokio::test]
async fn test_login_password() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;
    Ok(())
}

#[tokio::test]
async fn test_login_system_scope() -> Result<()> {
    let mut admin_client = TestClient::default()?;

    let auth = IdentityBuilder::default()
        .methods(vec!["password".into()])
        .password(get_password_auth(
            "admin",
            env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or("password".to_string()),
            "default",
        )?)
        .build()?;

    admin_client
        .auth(auth, Some(Scope::System(System::default())))
        .await?;

    Ok(())
}
