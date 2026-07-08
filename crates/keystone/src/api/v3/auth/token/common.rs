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

use openstack_keystone_core::auth::ExecutionContext;

use crate::api::error::KeystoneApiError;
use crate::api::v3::auth::token::types::AuthRequest;
use crate::auth::*;
use crate::keystone::ServiceState;

/// Authenticate the user ignoring any scope information. It is important not to
/// expose any hints that user, project, domain, etc might exist before we have
/// authenticated them by taking different amount of time in case of certain
/// validations.
#[tracing::instrument(skip(state), err)]
pub(super) async fn authenticate_request(
    state: &ServiceState,
    req: &AuthRequest,
) -> Result<Vec<AuthenticationResult>, KeystoneApiError> {
    let mut res = Vec::new();
    for method in req.auth.identity.methods.iter() {
        if method == "password" {
            if let Some(password_auth) = &req.auth.identity.password {
                let req = password_auth.user.clone().try_into()?;
                res.push(
                    state
                        .provider
                        .get_identity_provider()
                        .authenticate_by_password(&ExecutionContext::internal(state), &req)
                        .await?,
                );
            }
        } else if method == "totp" {
            if let Some(totp_auth) = &req.auth.identity.totp {
                let req = totp_auth.user.clone().try_into()?;
                res.push(
                    state
                        .provider
                        .get_identity_provider()
                        .authenticate_by_totp(&ExecutionContext::internal(state), &req)
                        .await?,
                );
            }
        } else if method == "token"
            && let Some(token) = &req.auth.identity.token
        {
            let vsc = state
                .provider
                .get_token_provider()
                .authorize_by_token(
                    &ExecutionContext::internal(state),
                    &token.id,
                    Some(false),
                    None,
                )
                .await?;
            let auth_res = AuthenticationResult {
                audit_id: vsc.inner().audit_ids().first().cloned().unwrap_or_default(),
                context: vsc.inner().authentication_context().clone(),
                expires_at: vsc.inner().expires_at(),
                principal: vsc.inner().principal().clone(),
                authorization: vsc.inner().authorization().cloned(),
                token_restriction: vsc.inner().token_restriction().cloned(),
            };
            res.push(auth_res);
        }
    }
    if res.is_empty() {
        return Err(KeystoneApiError::UnauthorizedNoContext);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::auth::*;
    use openstack_keystone_core_types::identity::{UserPasswordAuthRequest, UserResponseBuilder};
    use openstack_keystone_core_types::resource::Domain;
    use secrecy::ExposeSecret;

    use super::super::types::*;
    use super::*;
    use crate::api::KeystoneApiError;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::token::MockTokenProvider;

    #[tokio::test]
    async fn test_authenticate_request_password() {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let auth_clone = auth.clone();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .withf(|_, req: &UserPasswordAuthRequest| {
                req.id == Some("uid".to_string())
                    && req.password.expose_secret() == "pwd"
                    && req.name == Some("uname".to_string())
            })
            .returning(move |_, _| Ok(auth_clone.clone()));

        let provider = Provider::mocked_builder().mock_identity(identity_mock);

        let state = get_mocked_state(provider, true, None).await;

        assert_eq!(
            vec![auth],
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["password".to_string()],
                            password: Some(PasswordAuth {
                                user: UserPasswordBuilder::default()
                                    .id("uid")
                                    .password("pwd")
                                    .name("uname")
                                    .build()
                                    .unwrap(),
                            }),
                            token: None,
                            totp: None,
                        },
                        scope: None,
                    },
                }
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_authenticate_request_totp() {
        use openstack_keystone_core_types::identity::UserTotpAuthRequest;

        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Totp)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let auth_clone = auth.clone();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_totp()
            .withf(|_, req: &UserTotpAuthRequest| {
                req.id == Some("uid".to_string()) && req.passcode.expose_secret() == "123456"
            })
            .returning(move |_, _| Ok(auth_clone.clone()));

        let provider = Provider::mocked_builder().mock_identity(identity_mock);

        let state = get_mocked_state(provider, true, None).await;

        assert_eq!(
            vec![auth],
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["totp".to_string()],
                            password: None,
                            token: None,
                            totp: Some(TotpAuth {
                                user: TotpUserBuilder::default()
                                    .id("uid")
                                    .passcode("123456")
                                    .build()
                                    .unwrap(),
                            }),
                        },
                        scope: None,
                    },
                }
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_authenticate_request_token() {
        let user = UserResponseBuilder::default()
            .id("uid")
            .domain_id("user_domain_id")
            .enabled(true)
            .name("name")
            .build()
            .unwrap();
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Token(
                openstack_keystone_core_types::token::FernetToken::Unscoped(
                    openstack_keystone_core_types::token::UnscopedPayload::default(),
                ),
            ))
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user.clone())
                        .user_domain(Domain {
                            id: "user_domain_id".into(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let vsc_for_mock = {
            let sc = SecurityContext::try_from(auth.clone()).unwrap();
            openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
        };
        let vsc_clone = vsc_for_mock.clone();
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_authorize_by_token()
            .withf(
                |_,
                 _id: &secrecy::SecretString,
                 allow_expired: &Option<bool>,
                 window: &Option<i64>| {
                    *allow_expired == Some(false) && window.is_none()
                },
            )
            .returning(move |_state, _, _, _| Ok(vsc_clone.clone()));
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_exec, id: &'_ str| id == "uid")
            .returning(move |_exec, _| Ok(Some(user.clone())));

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_token(token_mock);

        let state = get_mocked_state(provider, true, None).await;

        assert_eq!(
            vec![auth],
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["token".to_string()],
                            password: None,
                            token: Some(TokenAuth {
                                id: "fake_token".into()
                            }),
                            totp: None,
                        },
                        scope: None,
                    },
                }
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_authenticate_request_unsupported() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let rsp = authenticate_request(
            &state,
            &AuthRequest {
                auth: AuthRequestInner {
                    identity: Identity {
                        methods: vec!["fake".to_string()],
                        password: None,
                        token: None,
                        totp: None,
                    },
                    scope: None,
                },
            },
        )
        .await;
        if let KeystoneApiError::UnauthorizedNoContext = rsp.unwrap_err() {
        } else {
            panic!("Should receive Unauthorized");
        }
    }
}
