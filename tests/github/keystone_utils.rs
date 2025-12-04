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

use eyre::Report;
use reqwest::Client;
use serde_json::json;
use std::env;

use openstack_keystone::api::v4::federation::types::*;
use openstack_keystone::api::v4::user::types::*;

pub async fn auth() -> String {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();
    client
        .post(format!("{}/v3/auth/tokens", keystone_url,))
        .json(&json!({"auth": {"identity": {
            "methods": [
                "password"
            ],
            "password": {
                "user": {
                    "name": "admin",
                    "password": "password",
                    "domain": {
                        "id": "default"
                    },
                }
            }
        },
        "scope": {
            "project": {
                "name": "admin",
                "domain": {"id": "default"}
            }
        }}}))
        .send()
        .await
        .unwrap()
        .headers()
        .get("X-Subject-Token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

pub async fn setup_github_idp<T: AsRef<str>>(
    token: T,
    user: &User,
) -> Result<(IdentityProviderResponse, MappingResponse), Report> {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let github_sub = env::var("GITHUB_SUB").expect("GITHUB_SUB is set");
    let client = Client::new();

    let idp: IdentityProviderResponse = client
        .post(format!("{}/v4/federation/identity_providers", keystone_url))
        .header("x-auth-token", token.as_ref())
        .json(&json!({
            "identity_provider": {
                "id": "github",
                "name": "github",
                "enabled": true,
                "bound_issuer": "https://token.actions.githubusercontent.com",
                "jwks_url": "https://token.actions.githubusercontent.com/.well-known/jwks",
             }
        }))
        .send()
        .await?
        .json()
        .await?;

    let mapping: MappingResponse = client
        .post(format!("{}/v4/federation/mappings", keystone_url,))
        .header("x-auth-token", token.as_ref())
        .json(&json!({
            "mapping": {
                "id": "github",
                "name": "github",
                "type": "jwt",
                "enabled": true,
                "idp_id": idp.identity_provider.id.clone(),
                "domain_id": user.domain_id,
                "bound_audiences": vec!["https://github.com"],
                "bound_claims": {
                    "base_ref": "main"
                },
                "bound_subject": github_sub,
                "user_id_claim": "actor_id",
                "user_name_claim": "actor",
                "token_user_id": user.id
             }
        }))
        .send()
        .await?
        .json()
        .await?;

    Ok((idp, mapping))
}

pub async fn ensure_user<T: AsRef<str>, U: AsRef<str>, D: AsRef<str>>(
    token: T,
    user_name: U,
    domain_id: D,
) -> Result<User, Report> {
    let keystone_url = env::var("KEYSTONE_URL").expect("KEYSTONE_URL is set");
    let client = Client::new();

    let user_rsp = client
        .post(format!("{}/v4/users", keystone_url))
        .header("x-auth-token", token.as_ref())
        .json(&json!({
            "user": {
                "name": user_name.as_ref(),
                "domain_id": domain_id.as_ref()
             }
        }))
        .send()
        .await?;
    if !user_rsp.status().is_success() {
        return Ok(client
            .get(format!("{}/v4/users", keystone_url))
            .query(&[
                ("domain_id", domain_id.as_ref()),
                ("name", user_name.as_ref()),
            ])
            .header("x-auth-token", token.as_ref())
            .send()
            .await?
            .json::<UserList>()
            .await?
            .users
            .first()
            .expect("cannot find user")
            .clone());
    }
    let user: UserResponse = user_rsp.json().await?;

    Ok(user.user)
}
