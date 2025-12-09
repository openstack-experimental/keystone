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

use eyre::{OptionExt, Report};
use keycloak::{KeycloakAdmin, KeycloakAdminToken, KeycloakError, types::*};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

pub async fn get_keycloak_admin(client: &Client) -> Result<KeycloakAdmin, Report> {
    let url = std::env::var("KEYCLOAK_URL").unwrap_or_else(|_| "http://localhost:8082".into());
    let user = std::env::var("KEYCLOAK_USER").unwrap_or_else(|_| "admin".into());
    let password = std::env::var("KEYCLOAK_PASSWORD").unwrap_or_else(|_| "password".into());

    let admin_token = KeycloakAdminToken::acquire(&url, &user, &password, client).await?;

    Ok(KeycloakAdmin::new(&url, admin_token, client.clone()))
}

pub async fn create_keycloak_client<S1: AsRef<str>, S2: AsRef<str>>(
    admin: &KeycloakAdmin,
    client_id: S1,
    client_secret: S2,
) -> Result<(), Report> {
    let realm = "master";
    let keystone_client_req = ClientRepresentation {
        client_id: Some(client_id.as_ref().into()),
        name: Some(client_id.as_ref().into()),
        secret: Some(client_secret.as_ref().into()),
        redirect_uris: vec!["http://localhost:8050/*".into()].into(),
        protocol_mappers: vec![
            ProtocolMapperRepresentation {
                name: Some("domain_id".into()),
                protocol: Some("openid-connect".into()),
                protocol_mapper: Some("oidc-hardcoded-claim-mapper".into()),
                config: Some(HashMap::from([
                    ("claim.name".into(), "domain_id".into()),
                    ("claim.value".into(), "default".into()),
                    ("access.tokenResponse.claim".into(), "false".into()),
                    ("access.token.claim".into(), "true".into()),
                    ("userinfo.token.claim".into(), "true".into()),
                    ("id.token.claim".into(), "true".into()),
                ])),
                ..Default::default()
            },
            ProtocolMapperRepresentation {
                name: Some("groups".into()),
                protocol: Some("openid-connect".into()),
                protocol_mapper: Some("oidc-group-membership-mapper".into()),
                config: Some(HashMap::from([
                    ("claim.name".into(), "groups".into()),
                    ("access.tokenResponse.claim".into(), "false".into()),
                    ("access.token.claim".into(), "true".into()),
                    ("userinfo.token.claim".into(), "true".into()),
                    ("id.token.claim".into(), "true".into()),
                ])),
                ..Default::default()
            },
        ]
        .into(),
        // allow generating JWT directly
        direct_access_grants_enabled: Some(true),
        ..Default::default()
    };
    match admin.realm_clients_post(realm, keystone_client_req).await {
        Ok(_) | Err(KeycloakError::HttpFailure { status: 409, .. }) => Ok(()),
        Err(err) => Err(err)?,
    }
}

pub async fn create_keycloak_user<U: AsRef<str>, P: AsRef<str>>(
    admin: &KeycloakAdmin,
    username: U,
    password: P,
) -> Result<String, Report> {
    let realm = "master";
    let user_req = UserRepresentation {
        username: Some(username.as_ref().into()),
        credentials: Some(vec![CredentialRepresentation {
            type_: Some("password".into()),
            value: Some(password.as_ref().into()),
            temporary: Some(false),
            user_label: Some("Password".into()),
            ..Default::default()
        }]),
        enabled: Some(true),
        ..Default::default()
    };
    match admin.realm_users_post(realm, user_req).await {
        Ok(rsp) => rsp
            .to_id()
            .map(|val| val.to_string())
            .ok_or_eyre("no ID in the user creation response"),
        Err(KeycloakError::HttpFailure { status: 409, .. }) => Ok(admin
            .realm_users_get(
                realm,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(username.as_ref().into()),
            )
            .await?
            .first()
            .map(|res| res.id.clone().expect("user must contain id"))
            .expect("user found")),
        Err(err) => Err(err)?,
    }
}

pub async fn create_keycloak_group<U: AsRef<str>>(
    admin: &KeycloakAdmin,
    name: U,
) -> Result<String, Report> {
    let realm = "master";
    let group_req = GroupRepresentation {
        name: Some(name.as_ref().into()),
        ..Default::default()
    };
    match admin.realm_groups_post(realm, group_req).await {
        Ok(rsp) => rsp
            .to_id()
            .map(|val| val.to_string())
            .ok_or_eyre("no group created"),
        Err(KeycloakError::HttpFailure { status: 409, .. }) => Ok(admin
            .realm_groups_get(
                realm,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(name.as_ref().to_string()),
                None,
            )
            .await?
            .first()
            .map(|group| group.id.clone().expect("group must contain id"))
            .expect("group found")),
        Err(err) => Err(err)?,
    }
}

pub async fn put_user_to_group<U: AsRef<str>, G: AsRef<str>>(
    admin: &KeycloakAdmin,
    user_id: U,
    group_id: G,
) -> Result<(), Report> {
    let realm = "master";
    match admin
        .realm_users_with_user_id_groups_with_group_id_put(
            realm,
            user_id.as_ref(),
            group_id.as_ref(),
        )
        .await
    {
        Ok(_) | Err(KeycloakError::HttpFailure { status: 409, .. }) => Ok(()),
        Err(err) => Err(err)?,
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub id_token: String,
}

pub async fn generate_user_jwt(
    client_id: &'static str,
    client_secret: &'static str,
    user: &'static str,
    password: &'static str,
) -> Result<String, Report> {
    let client = Client::new();
    let url = std::env::var("KEYCLOAK_URL").unwrap_or_else(|_| "http://localhost:8082".into());
    let realm = "master";
    let response: AuthResponse = client
        .post(format!(
            "{}/realms/{}/protocol/openid-connect/token",
            url, realm
        ))
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("username", user),
            ("password", password),
            ("scope", "openid"),
            ("grant_type", "password"),
        ])
        .send()
        .await?
        .json()
        .await?;
    Ok(response.id_token)
}
