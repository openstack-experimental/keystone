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

use openstack_keystone::api::v3::auth::token::types::*;

use crate::auth::token::check_token;
use crate::common::*;

#[tokio::test]
async fn test_validate_own() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;

    let _auth_rsp: TokenResponse = check_token(
        &admin_client,
        admin_client.token.as_ref().expect("must be authenticated"),
    )
    .await?
    .json()
    .await?;
    Ok(())
}
