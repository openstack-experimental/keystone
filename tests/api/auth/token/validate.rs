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

use reqwest::Client;
use std::env;

use openstack_keystone::api::types::*;
use openstack_keystone::api::v3::auth::token::types::*;

use crate::common::*;

#[tokio::test]
async fn test_validate_own() {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();

    let token = auth(
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

    let _auth_rsp: TokenResponse =
        check_token(&client, keystone_url.clone(), token.clone(), token.clone())
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
}
