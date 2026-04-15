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

//use std::time;

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use eyre::{Result, eyre};
use reqwest::Client;
use reserve_port::ReservedSocketAddr;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softtoken::SoftToken;

use openstack_keystone_api_types::webauthn::*;
use openstack_keystone_core::identity::MockIdentityProvider;
use openstack_keystone_core::provider::{Provider, ProviderBuilder};
use openstack_keystone_core::resource::MockResourceProvider;
use openstack_keystone_core::token::{MockTokenProvider, Token, UnscopedPayload};
use openstack_keystone_core_types::identity::UserResponseBuilder;
use openstack_keystone_core_types::resource::{Domain, Project};
use openstack_keystone_core_types::token::{ProjectScopePayload, Token as ProviderToken};
use openstack_keystone_webauthn::api::init_extension;

mod common;
use common::get_state;

fn get_provider_mocks(user_id: &Uuid) -> ProviderBuilder {
    let provider_builder = Provider::mocked_builder();
    let mut token_mock = MockTokenProvider::default();
    let uid = user_id.to_string().clone();
    token_mock
        .expect_validate_token()
        .returning(move |_, _, _, _| {
            Ok(Token::Unscoped(UnscopedPayload {
                user_id: uid.clone(),
                user: Some(
                    UserResponseBuilder::default()
                        .id(uid.clone())
                        .domain_id("udid")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ),
                ..Default::default()
            }))
        });
    let uid = user_id.to_string().clone();
    token_mock
        .expect_expand_token_information()
        .returning(move |_, _| {
            Ok(Token::Unscoped(UnscopedPayload {
                user_id: uid.clone(),
                ..Default::default()
            }))
        });
    let uid = user_id.to_string().clone();
    token_mock.expect_issue_token().returning(move |_, _, _| {
        Ok(ProviderToken::ProjectScope(ProjectScopePayload {
            user_id: uid.clone(),
            methods: Vec::from(["x509".to_string()]),
            user: Some(
                UserResponseBuilder::default()
                    .id("uid")
                    .domain_id("user_domain_id")
                    .enabled(true)
                    .name("name")
                    .build()
                    .unwrap(),
            ),
            project_id: "pid".into(),
            ..Default::default()
        }))
    });
    token_mock
        .expect_encode_token()
        .returning(|_| Ok("token".to_string()));
    let mut identity_mock = MockIdentityProvider::default();
    let uid = user_id.to_string().clone();
    identity_mock.expect_get_user().returning(move |_, _| {
        Ok(Some(
            UserResponseBuilder::default()
                .id(uid.clone())
                .domain_id("user_domain_id")
                .enabled(true)
                .name("name")
                .build()
                .unwrap(),
        ))
    });
    let mut resource_mock = MockResourceProvider::default();

    let project = Project {
        id: "pid".into(),
        domain_id: "pdid".into(),
        enabled: true,
        ..Default::default()
    };
    let user_domain = Domain {
        id: "user_domain_id".into(),
        enabled: true,
        ..Default::default()
    };
    let project_domain = Domain {
        id: "pdid".into(),
        enabled: true,
        ..Default::default()
    };
    resource_mock
        .expect_get_project()
        .withf(|_, id: &'_ str| id == "pid")
        .returning(move |_, _| Ok(Some(project.clone())));
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "user_domain_id")
        .returning(move |_, _| Ok(Some(user_domain.clone())));
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "pdid")
        .returning(move |_, _| Ok(Some(project_domain.clone())));

    provider_builder
        .mock_token(token_mock)
        .mock_identity(identity_mock)
        .mock_resource(resource_mock)
}

#[tracing_test::traced_test]
#[tokio::test]
async fn test_webauthn_roundtrip() -> Result<()> {
    let user_id = Uuid::new_v4();

    let (state, _dir) = get_state(Some(get_provider_mocks(&user_id))).await?;

    let authenticator_backend = SoftToken::new(true)?.0;
    let origin = Url::parse("https://keystone.local")?;
    let mut authenticator = WebauthnAuthenticator::new(authenticator_backend);

    let addr = ReservedSocketAddr::reserve_random_socket_addr()?.socket_addr();
    let cancel_token = CancellationToken::new();

    let listener = TcpListener::bind(&addr).await?;

    let mut handles = tokio::task::JoinSet::new();

    let middleware = ServiceBuilder::new().layer(
        TraceLayer::new_for_http()
            .make_span_with(DefaultMakeSpan::new().include_headers(true))
            .on_request(DefaultOnRequest::new().level(Level::INFO))
            .on_response(DefaultOnResponse::new().level(Level::INFO)),
    );
    let app = init_extension(state.core.clone(), cancel_token)?.layer(middleware);
    handles.spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let client = Client::new();
    let ccr = client
        .post(format!(
            "http://{}/users/{}/passkeys/register_start",
            addr,
            user_id.to_string()
        ))
        .header("x-auth-token", "fake")
        .json(&json!(UserPasskeyRegistrationStartRequest {
            passkey: PasskeyCreate { description: None }
        }))
        .send()
        .await?
        .json::<UserPasskeyRegistrationStartResponse>()
        .await?;

    // register soft key
    let reg_result = authenticator.do_registration(
        origin.clone(),
        webauthn_authenticator_rs::prelude::CreationChallengeResponse {
            public_key: ccr.public_key.try_into()?,
        },
    )?;
    let finish_req: UserPasskeyRegistrationFinishRequest = reg_result.into();
    //finish_req.description = Some("another description".into());
    // TODO: check description (not used what is sent in initial request)

    // finish registration
    let passkey = client
        .post(format!(
            "http://{}/users/{}/passkeys/register_finish",
            addr,
            user_id.to_string()
        ))
        .header("x-auth-token", "fake")
        .json(&serde_json::to_value(&finish_req)?)
        .send()
        .await?
        .json::<PasskeyResponse>()
        .await?;

    // Check the credential is actually saved in the storage
    state
        .extension
        .provider
        .get_user_webauthn_credential(
            &state.core,
            &user_id.to_string(),
            &passkey.passkey.credential_id,
        )
        .await?
        .expect("must be found");

    // now start auth
    let auth_challenge = client
        .post(format!("http://{}/auth/passkey/start", addr,))
        .json(&serde_json::to_value(&PasskeyAuthenticationStartRequest {
            passkey: PasskeyUserAuthenticationRequest {
                user_id: user_id.to_string(),
            },
        })?)
        .send()
        .await?
        .json::<PasskeyAuthenticationStartResponse>()
        .await?;

    // authenticate locally
    let auth_challenge_response = authenticator.do_authentication(
        origin,
        webauthn_authenticator_rs::prelude::RequestChallengeResponse {
            public_key: auth_challenge.public_key.try_into()?,
            mediation: auth_challenge.mediation.map(Into::into),
        },
    )?;

    // finish the auth
    let rsp = client
        .post(format!("http://{}/auth/passkey/finish", addr,))
        .json(&serde_json::to_value(
            &PasskeyAuthenticationFinishRequest {
                id: auth_challenge_response.id,
                extensions: auth_challenge_response.extensions.into(),
                raw_id: URL_SAFE.encode(auth_challenge_response.raw_id),
                response: auth_challenge_response.response.into(),
                type_: auth_challenge_response.type_,
                user_id: user_id.to_string(),
            },
        )?)
        .send()
        .await?;
    let _token = rsp
        .headers()
        .get("X-Subject-Token")
        .ok_or_else(|| eyre!("Token is missing in the {:?}", rsp))?
        .to_str()?
        .to_string();
    Ok(())
}
