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
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
use std::env;

use eyre::Report;
use reqwest::Client;
use serde::Deserialize;
use tracing_test::traced_test;

use openstack_keystone_api_types::federation::*;
use openstack_keystone_api_types::v4::mapping::*;
use openstack_keystone_api_types::v4::user::*;

mod keystone_utils;

use keystone_utils::*;

/// Response from GitHub's OIDC token endpoint.
#[derive(Deserialize)]
struct IdpTokenResponse {
    value: String,
}

/// Resolve GitHub JWT: prefer `GITHUB_JWT`, then fetch via Actions OIDC API, then skip.
async fn resolve_jwt() -> Option<String> {
    // Direct JWT provided
    if let Ok(jwt) = env::var("GITHUB_JWT") {
        if !jwt.is_empty() {
            return Some(jwt);
        }
    }

    // Fetch from GitHub OIDC endpoint
    let request_token = match env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return None,
    };
    let request_url = match env::var("ACTIONS_ID_TOKEN_REQUEST_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => return None,
    };

    let audience =
        env::var("ACTIONS_ID_TOKEN_AUDIENCE").unwrap_or_else(|_| "https://github.com".to_string());
    let url = format!("{request_url}&audience={audience}");

    let resp = Client::new()
        .get(&url)
        .header("Authorization", format!("bearer {request_token}"))
        .send()
        .await
        .ok()?;
    let body = resp.json::<IdpTokenResponse>().await.ok()?;
    Some(body.value)
}

pub async fn setup_github_idp<T: AsRef<str>>(
    token: T,
    _user: &User,
) -> Result<(IdentityProvider, MappingRuleSet), Report> {
    let config = get_config();

    let idp = create_idp(
        config,
        token.as_ref(),
        IdentityProviderCreateRequest {
            identity_provider: IdentityProviderCreateBuilder::default()
                .name("github")
                .enabled(true)
                .domain_id("default")
                .default_mapping_name("github")
                .bound_issuer("https://token.actions.githubusercontent.com")
                .jwks_url("https://token.actions.githubusercontent.com/.well-known/jwks")
                .build()?,
        },
    )
    .await?;

    let ruleset = create_ruleset(
        config,
        token.as_ref(),
        MappingRuleSetCreateRequest {
            mapping: MappingRuleSetCreate {
                mapping_id: Some("github".into()),
                domain_id: Some("default".into()),
                source: IdentitySource::Federation {
                    idp_id: idp.id.clone(),
                },
                domain_resolution_mode: DomainResolutionMode::Fixed,
                enabled: true,
                rules: vec![MappingRule {
                    name: "github".into(),
                    description: None,
                    r#match: MatchCriteria::AllOf(Vec::new()),
                    identity: IdentityBinding {
                        identity_mode: Some(IdentityMode::Local),
                        user_name: "${claims.actor}".into(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: Vec::new(),
                    groups: Vec::new(),
                }],
            },
        },
    )
    .await?;

    Ok((idp, ruleset))
}

#[tokio::test]
#[traced_test]
async fn test_login_jwt() {
    let jwt = match resolve_jwt().await {
        Some(j) => j,
        None => {
            eprintln!("Skipping: no GitHub JWT available");
            return;
        }
    };

    let config = get_config();
    let token = auth(config).await;
    let user = ensure_user(&token, "jwt_user", "default").await.unwrap();
    let (idp, _ruleset) = setup_github_idp(&token, &user).await.unwrap();

    let _auth_rsp = auth_jwt(config, jwt, idp.id, idp.default_mapping_name.unwrap())
        .await
        .unwrap();
}
