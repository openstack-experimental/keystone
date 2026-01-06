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
use std::collections::HashSet;
use tracing_test::traced_test;

use crate::common::*;

pub async fn check_grant<
    P: AsRef<str> + std::fmt::Display,
    U: AsRef<str> + std::fmt::Display,
    R: AsRef<str> + std::fmt::Display,
>(
    client: &Client,
    project_id: P,
    user_id: U,
    role_id: R,
) -> Result<bool> {
    let rsp = client
        .head(build_url(format!(
            "v3/projects/{}/users/{}/roles/{}",
            project_id, user_id, role_id
        )))
        .send()
        .await?;
    Ok(rsp.status() == StatusCode::NO_CONTENT)
}

#[tokio::test]
#[traced_test]
async fn test_check() -> Result<()> {
    let client = Client::new();
    let admin_auth = get_admin_auth(&client).await?;
    let auth_token = admin_auth.0.token;
    let admin_client = get_auth_client(admin_auth.1).await?;
    let all_role_ids: HashSet<String> = list_roles(&admin_client)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();
    let user_role_ids: HashSet<String> = auth_token
        .roles
        .as_ref()
        .expect("roles must exist")
        .iter()
        .map(|r| r.id.clone())
        .collect();
    for role_id in user_role_ids.union(&all_role_ids) {
        let res = check_grant(
            &admin_client,
            &auth_token.project.as_ref().expect("project must exist").id,
            &auth_token.user.id,
            &role_id,
        )
        .await?;
        if user_role_ids.contains(role_id) {
            assert!(res);
        } else {
            assert!(
                !res,
                "role_id {} is not granted to the user {:?}",
                role_id, auth_token
            );
        }
    }
    Ok(())
}
