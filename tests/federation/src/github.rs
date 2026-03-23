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
use std::collections::HashMap;
use std::env;

use eyre::Report;
use serde_json::json;
use tracing_test::traced_test;

use openstack_keystone_api_types::federation::*;
use openstack_keystone_api_types::v4::user::*;

mod keystone_utils;

use keystone_utils::*;

pub async fn setup_github_idp<T: AsRef<str>>(
    token: T,
    user: &User,
) -> Result<(IdentityProvider, Mapping), Report> {
    let config = get_config();
    let github_sub = env::var("GITHUB_SUB").expect("GITHUB_SUB is set");

    let idp = create_idp(
        config,
        token.as_ref(),
        IdentityProviderCreateRequest {
            identity_provider: IdentityProviderCreateBuilder::default()
                .name("github")
                .enabled(true)
                .bound_issuer("https://token.actions.githubusercontent.com")
                .jwks_url("https://token.actions.githubusercontent.com/.well-known/jwks")
                .build()?,
        },
    )
    .await?;

    let mapping = create_mapping(
        config,
        token.as_ref(),
        MappingCreateRequest {
            mapping: MappingCreateBuilder::default()
                .id("github")
                .name("github")
                .r#type(MappingType::Jwt)
                .enabled(true)
                .idp_id(idp.id.clone())
                .domain_id(user.domain_id.clone())
                .bound_audiences(vec!["https://github.com".into()])
                .bound_claims(HashMap::from([("base_ref".into(), json!("main"))]))
                .bound_subject(github_sub)
                .user_id_claim("actor_id")
                .user_name_claim("actor")
                .build()?,
        },
    )
    .await?;

    Ok((idp, mapping))
}

#[tokio::test]
#[traced_test]
async fn test_login_jwt() {
    let config = get_config();
    let jwt = env::var("GITHUB_JWT").expect("GITHUB_JWT is set");

    let token = auth(config).await;
    let user = ensure_user(&token, "jwt_user", "default").await.unwrap();
    let (idp, mapping) = setup_github_idp(&token, &user).await.unwrap();

    let _auth_rsp = auth_jwt(config, jwt, idp.id, mapping.name).await.unwrap();
}
