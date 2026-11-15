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

//! Checks the real Keycloak inputs for the token exchange suite (#1366).

use std::{collections::HashMap, env, time::Duration};

use ::keycloak::types::{
    ClientRepresentation, CredentialRepresentation, ProtocolMapperRepresentation,
    RealmRepresentation, UserRepresentation,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use eyre::{OptionExt, Report, WrapErr, ensure};
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

mod keystone_utils;
mod keycloak {
    #[allow(dead_code)]
    pub mod utils;
}

#[derive(Deserialize)]
struct Discovery {
    token_endpoint: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Deserialize)]
struct SubjectClaims {
    iss: String,
    aud: Audience,
    sub: String,
    preferred_username: String,
    jti: String,
    iat: u64,
    exp: u64,
}

fn client_config(id: &str, secret: &str, audience: &str) -> ClientRepresentation {
    ClientRepresentation {
        client_id: Some(id.into()),
        secret: Some(secret.into()),
        enabled: Some(true),
        public_client: Some(false),
        client_authenticator_type: Some("client-secret".into()),
        protocol: Some("openid-connect".into()),
        standard_flow_enabled: Some(false),
        direct_access_grants_enabled: Some(true),
        service_accounts_enabled: Some(true),
        // Exclude the "roles" scope and its audience resolver. The subject
        // profile requires the Keystone token endpoint as the sole audience.
        default_client_scopes: vec!["profile".into()].into(),
        protocol_mappers: vec![ProtocolMapperRepresentation {
            name: Some("keystone-token-endpoint".into()),
            protocol: Some("openid-connect".into()),
            protocol_mapper: Some("oidc-audience-mapper".into()),
            config: Some(HashMap::from([
                ("included.custom.audience".into(), audience.into()),
                ("access.token.claim".into(), "true".into()),
            ])),
            ..Default::default()
        }]
        .into(),
        ..Default::default()
    }
}

async fn issue_subject(
    client: &Client,
    issuer: &str,
    form: &[(&str, &str)],
) -> Result<SubjectClaims, Report> {
    let response: TokenResponse = client
        .post(format!("{issuer}/protocol/openid-connect/token"))
        .form(form)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .wrap_err("read Keycloak token response")?;
    let mut segments = response.access_token.split('.');
    let header = segments.next().filter(|part| !part.is_empty());
    let payload = segments
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_eyre("Keycloak token has no JWT payload")?;
    ensure!(
        header.is_some()
            && segments.next().is_some_and(|part| !part.is_empty())
            && segments.next().is_none(),
        "Keycloak token is not a signed compact JWT"
    );
    // Read the claims of our fixture to check how Keycloak minted it. This
    // does not verify a JWT or substitute for the exchange under test.
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)
        .wrap_err("decode claims from the Keycloak fixture")
}

fn check_claims(claims: &SubjectClaims, issuer: &str, audience: &str, user: &str) {
    assert_eq!(claims.iss, issuer);
    match &claims.aud {
        Audience::Single(aud) => assert_eq!(aud, audience),
        Audience::Multiple(aud) => assert_eq!(aud, &[audience]),
    }
    assert_eq!(claims.preferred_username, user);
    assert!(!claims.sub.is_empty());
    assert!(!claims.jti.is_empty());
    assert!(matches!(claims.exp.checked_sub(claims.iat), Some(1..=300)));
}

#[tokio::test]
async fn keycloak_issues_user_and_service_account_subjects() -> Result<(), Report> {
    let keystone = env::var("KEYSTONE_URL").wrap_err("KEYSTONE_URL must be set")?;
    let keycloak = env::var("KEYCLOAK_URL").wrap_err("KEYCLOAK_URL must be set")?;
    env::var("KEYCLOAK_PASSWORD").wrap_err("KEYCLOAK_PASSWORD must be set")?;
    let client = keystone_utils::http_client_builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let discovery: Discovery = client
        .get(format!(
            "{}/v4/oauth2/default/.well-known/openid-configuration",
            keystone.trim_end_matches('/')
        ))
        .send()
        .await
        .wrap_err("reach Keystone OAuth2 discovery")?
        .error_for_status()?
        .json()
        .await?;

    let admin = keycloak::utils::get_keycloak_admin(&client)
        .await
        .wrap_err("authenticate to Keycloak")?;
    let realm = format!("exchange-{}", Uuid::new_v4().simple());
    let issuer = format!("{}/realms/{realm}", keycloak.trim_end_matches('/'));
    let client_id = "exchange-fixture";
    let user = "exchange-user";
    let secret = Uuid::new_v4().to_string();
    let password = Uuid::new_v4().to_string();
    admin
        .post(RealmRepresentation {
            realm: Some(realm.clone()),
            enabled: Some(true),
            ssl_required: Some("none".into()),
            access_token_lifespan: Some(120),
            ..Default::default()
        })
        .await
        .wrap_err("create isolated Keycloak realm")?;

    let issued = async {
        admin
            .realm_clients_post(
                &realm,
                client_config(client_id, &secret, &discovery.token_endpoint),
            )
            .await
            .wrap_err("configure Keycloak client and audience")?;
        admin
            .realm_users_post(
                &realm,
                UserRepresentation {
                    username: Some(user.into()),
                    enabled: Some(true),
                    first_name: Some("Exchange".into()),
                    last_name: Some("Fixture".into()),
                    email: Some("exchange-fixture@example.invalid".into()),
                    credentials: vec![CredentialRepresentation {
                        type_: Some("password".into()),
                        value: Some(password.clone()),
                        temporary: Some(false),
                        ..Default::default()
                    }]
                    .into(),
                    ..Default::default()
                },
            )
            .await
            .wrap_err("create Keycloak test user")?;

        let user_claims = issue_subject(
            &client,
            &issuer,
            &[
                ("grant_type", "password"),
                ("client_id", client_id),
                ("client_secret", &secret),
                ("username", user),
                ("password", &password),
            ],
        )
        .await
        .wrap_err("issue a user JWT")?;
        let service_claims = issue_subject(
            &client,
            &issuer,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", &secret),
            ],
        )
        .await
        .wrap_err("issue a service account JWT")?;
        Ok::<_, Report>((user_claims, service_claims))
    }
    .await;

    let cleanup = admin
        .realm_delete(&realm)
        .await
        .wrap_err("delete isolated Keycloak realm");
    let (user_claims, service_claims) = issued?;
    cleanup?;

    check_claims(&user_claims, &issuer, &discovery.token_endpoint, user);
    check_claims(
        &service_claims,
        &issuer,
        &discovery.token_endpoint,
        &format!("service-account-{client_id}"),
    );
    assert_ne!(user_claims.sub, service_claims.sub);
    assert_ne!(user_claims.jti, service_claims.jti);
    Ok(())
}
