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
use reqwest::StatusCode;
use secrecy::ExposeSecret;
use tracing_test::traced_test;

use openstack_keystone::api::types::*;

use crate::auth::token::*;
use crate::common::*;

#[tokio::test]
#[traced_test]
async fn test_revoke() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;

    let mut test_client = TestClient::default()?;
    test_client.auth_admin().await?;
    let test_token = test_client.token.as_ref().expect("must be authenticated");

    check_token(&admin_client, test_token).await?;

    let rsp = admin_client
        .client
        .delete(admin_client.base_url.join("v3/auth/tokens")?)
        .header("x-subject-token", test_token.expose_secret())
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT);

    let rsp = check_token(&admin_client, test_token).await?;
    assert_eq!(rsp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_revoke_parent_invalidates_child() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;

    let mut parent_client = TestClient::default()?;
    parent_client.auth_admin().await?;
    let parent_token = parent_client.token.as_ref().expect("must be authenticated");

    let mut child_client = TestClient::default()?;
    child_client
        .auth_token(
            &parent_token.expose_secret(),
            Some(Scope::Project(
                ScopeProjectBuilder::default()
                    .name("admin")
                    .domain(DomainBuilder::default().id("default").build()?)
                    .build()?,
            )),
        )
        .await?;

    let child_token = child_client.token.as_ref().expect("must be authenticated");

    check_token(&admin_client, parent_token).await?;

    check_token(&admin_client, child_token).await?;

    let rsp = admin_client
        .client
        .delete(admin_client.base_url.join("v3/auth/tokens")?)
        .header("x-subject-token", parent_token.expose_secret())
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT, "token can be revoked");

    assert_eq!(
        StatusCode::NOT_FOUND,
        check_token(&admin_client, parent_token).await?.status()
    );

    assert_eq!(
        StatusCode::NOT_FOUND,
        check_token(&admin_client, child_token).await?.status()
    );
    Ok(())
}
