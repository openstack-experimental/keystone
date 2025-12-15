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

use reqwest::{Client, StatusCode};
use std::env;
use tracing_test::traced_test;

use openstack_keystone::api::types::*;
use openstack_keystone::api::v3::auth::token::types::*;

use crate::common::*;

#[tokio::test]
#[traced_test]
async fn test_revoke() {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();

    let admin_token = auth(
        &keystone_url,
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
    .expect("no token");

    let test_token = auth(
        &keystone_url,
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
    .expect("no token");

    let _auth_rsp: TokenResponse = check_token(
        &client,
        keystone_url.clone(),
        admin_token.clone(),
        test_token.clone(),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let rsp = client
        .delete(format!("{}/v3/auth/tokens", keystone_url))
        .header("x-auth-token", admin_token.clone())
        .header("x-subject-token", test_token.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT);

    let rsp = client
        .get(format!("{}/v3/auth/tokens", keystone_url))
        .header("x-auth-token", admin_token.clone())
        .header("x-subject-token", test_token.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(rsp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[traced_test]
async fn test_revoke_parent_invalidates_child() {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();

    let admin_token = auth(
        &keystone_url,
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
    .expect("no token");

    let parent_token = auth(
        &keystone_url,
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
    .expect("no token");

    let child_token = auth_with_token(
        &keystone_url,
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

    let _auth_rsp: TokenResponse = check_token(
        &client,
        keystone_url.clone(),
        admin_token.clone(),
        parent_token.clone(),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let _auth_rsp: TokenResponse = check_token(
        &client,
        keystone_url.clone(),
        admin_token.clone(),
        child_token.clone(),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let rsp = client
        .delete(format!("{}/v3/auth/tokens", keystone_url))
        .header("x-auth-token", admin_token.clone())
        .header("x-subject-token", parent_token.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        StatusCode::NOT_FOUND,
        check_token(
            &client,
            keystone_url.clone(),
            admin_token.clone(),
            parent_token.clone(),
        )
        .await
        .unwrap()
        .status()
    );

    assert_eq!(
        StatusCode::NOT_FOUND,
        check_token(
            &client,
            keystone_url.clone(),
            admin_token.clone(),
            child_token.clone(),
        )
        .await
        .unwrap()
        .status()
    );
}
