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
use reqwest::{Client, StatusCode};
use std::env;
use tracing_test::traced_test;

use openstack_keystone::api::types::*;
use openstack_keystone::api::v3::auth::token::types::*;

use crate::common::*;

#[tokio::test]
#[traced_test]
async fn test_revoke() -> Result<()> {
    let client = Client::new();

    let admin_token = get_admin_auth(&client).await?.1;
    let auth_client = get_auth_client(&admin_token).await?;

    let test_token = auth(
        get_password_auth(
            "admin",
            env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or("password".to_string()),
            "default",
        )
        .expect("can't prepare password auth"),
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .name("admin")
                .domain(DomainBuilder::default().id("default").build().unwrap())
                .build()
                .unwrap(),
        )),
    )
    .await
    .expect("no token")
    .1;

    let _auth_rsp: TokenResponse = check_token(&auth_client, &test_token)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rsp = auth_client
        .delete(build_url("v3/auth/tokens"))
        .header("x-subject-token", test_token.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT);

    let rsp = auth_client
        .get(build_url("v3/auth/tokens"))
        .header("x-subject-token", test_token.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(rsp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_revoke_parent_invalidates_child() -> Result<()> {
    let client = Client::new();

    let admin_token = get_admin_auth(&client).await?.1;
    let auth_client = get_auth_client(&admin_token).await?;

    let parent_token = auth(
        get_password_auth(
            "admin",
            env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or("password".to_string()),
            "default",
        )
        .expect("can't prepare password auth"),
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .name("admin")
                .domain(DomainBuilder::default().id("default").build().unwrap())
                .build()
                .unwrap(),
        )),
    )
    .await
    .expect("no token")
    .1;

    let child_token = auth_with_token(
        &parent_token,
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .name("admin")
                .domain(DomainBuilder::default().id("default").build().unwrap())
                .build()
                .unwrap(),
        )),
    )
    .await
    .expect("no token");

    let _auth_rsp: TokenResponse = check_token(&auth_client, &parent_token)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let _auth_rsp: TokenResponse = check_token(&auth_client, &child_token)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rsp = auth_client
        .delete(build_url("v3/auth/tokens"))
        .header("x-subject-token", parent_token.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT, "token can be revoked");

    assert_eq!(
        StatusCode::NOT_FOUND,
        check_token(&auth_client, parent_token.clone(),)
            .await
            .unwrap()
            .status()
    );

    assert_eq!(
        StatusCode::NOT_FOUND,
        check_token(&auth_client, child_token.clone(),)
            .await
            .unwrap()
            .status()
    );
    Ok(())
}
