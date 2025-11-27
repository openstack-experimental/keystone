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

use crate::api::common;
use crate::api::types::ProjectBuilder;
use crate::api::v3::auth::token::types::AuthRequest;
use crate::api::{
    Scope,
    common::{find_project_from_scope, get_domain},
    error::KeystoneApiError,
};
use crate::auth::{AuthenticatedInfo, AuthzInfo};
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::resource::types::{Domain, Project};
use crate::token::TokenApi;

/// Get the ProjectBuilder for the given Project.
pub(super) async fn get_project_info_builder(
    state: &ServiceState,
    project: &Project,
    user_domain: &Domain,
) -> Result<ProjectBuilder, KeystoneApiError> {
    let mut project_response = ProjectBuilder::default();
    project_response.id(project.id.clone());
    project_response.name(project.name.clone());
    if project.domain_id == user_domain.id {
        project_response.domain(user_domain.clone().into());
    } else {
        let project_domain =
            common::get_domain(state, Some(&project.domain_id), None::<&str>).await?;
        project_response.domain(project_domain.clone().into());
    }
    Ok(project_response)
}

/// Authenticate the user ignoring any scope information. It is important not to
/// expose any hints that user, project, domain, etc might exist before we have
/// authenticated them by taking different amount of time in case of certain
/// validations.
pub(super) async fn authenticate_request(
    state: &ServiceState,
    req: &AuthRequest,
) -> Result<AuthenticatedInfo, KeystoneApiError> {
    let mut authenticated_info: Option<AuthenticatedInfo> = None;
    for method in req.auth.identity.methods.iter() {
        if method == "password" {
            if let Some(password_auth) = &req.auth.identity.password {
                let req = password_auth.user.clone().try_into()?;
                authenticated_info = Some(
                    state
                        .provider
                        .get_identity_provider()
                        .authenticate_by_password(state, &req)
                        .await?,
                );
            }
        } else if method == "token"
            && let Some(token) = &req.auth.identity.token
        {
            let mut authz = state
                .provider
                .get_token_provider()
                .authenticate_by_token(state, &token.id, Some(false), None)
                .await?;
            // Resolve the user
            authz.user = Some(
                state
                    .provider
                    .get_identity_provider()
                    .get_user(state, &authz.user_id)
                    .await
                    .map(|x| {
                        x.ok_or_else(|| KeystoneApiError::NotFound {
                            resource: "user".into(),
                            identifier: authz.user_id.clone(),
                        })
                    })??,
            );
            authenticated_info = Some(authz);

            {}
        }
    }
    authenticated_info
        .ok_or(KeystoneApiError::Unauthorized(None))
        .and_then(|authn| {
            authn.validate()?;
            Ok(authn)
        })
}

/// Build the AuthZ information from the request
///
/// # Arguments
///
/// * `state` - The service state
/// * `req` - The Request
///
/// # Result
///
/// * `Ok(AuthzInfo)` - The AuthZ information
/// * `Err(KeystoneApiError)` - The error
pub(super) async fn get_authz_info(
    state: &ServiceState,
    req: &AuthRequest,
) -> Result<AuthzInfo, KeystoneApiError> {
    let authz_info = match &req.auth.scope {
        Some(Scope::Project(scope)) => {
            if let Some(project) = find_project_from_scope(state, scope).await? {
                AuthzInfo::Project(project)
            } else {
                return Err(KeystoneApiError::Unauthorized(None));
            }
        }
        Some(Scope::Domain(scope)) => {
            if let Ok(domain) = get_domain(state, scope.id.as_ref(), scope.name.as_ref()).await {
                AuthzInfo::Domain(domain)
            } else {
                return Err(KeystoneApiError::Unauthorized(None));
            }
        }
        Some(Scope::System(_scope)) => {
            todo!()
        }
        None => AuthzInfo::Unscoped,
    };
    authz_info.validate()?;
    Ok(authz_info)
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use crate::api::KeystoneApiError;

    use crate::auth::AuthenticatedInfo;
    use crate::config::Config;
    use crate::identity::{
        MockIdentityProvider,
        types::{UserPasswordAuthRequest, UserResponse},
    };
    use crate::keystone::Service;
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;

    use crate::token::MockTokenProvider;

    use super::super::types::*;
    use super::*;

    #[tokio::test]
    async fn test_authenticate_request_password() {
        let config = Config::default();
        let auth_info = AuthenticatedInfo::builder()
            .user_id("uid")
            .user(UserResponse {
                id: "uid".to_string(),
                domain_id: "udid".into(),
                enabled: true,
                ..Default::default()
            })
            .build()
            .unwrap();
        let auth_clone = auth_info.clone();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .withf(|_, req: &UserPasswordAuthRequest| {
                req.id == Some("uid".to_string())
                    && req.password == "pwd"
                    && req.name == Some("uname".to_string())
            })
            .returning(move |_, _| Ok(auth_clone.clone()));

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .identity(identity_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        assert_eq!(
            auth_info,
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["password".to_string()],
                            password: Some(PasswordAuth {
                                user: UserPassword {
                                    id: Some("uid".to_string()),
                                    password: "pwd".to_string(),
                                    name: Some("uname".to_string()),
                                    ..Default::default()
                                },
                            }),
                            token: None,
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
        let config = Config::default();

        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_authenticate_by_token()
            .withf(
                |_, id: &'_ str, allow_expired: &Option<bool>, window: &Option<i64>| {
                    id == "fake_token" && *allow_expired == Some(false) && window.is_none()
                },
            )
            .returning(|_, _, _, _| {
                Ok(AuthenticatedInfo::builder().user_id("uid").build().unwrap())
            });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "uid")
            .returning(|_, id: &'_ str| {
                Ok(Some(UserResponse {
                    id: id.to_string(),
                    domain_id: "user_domain_id".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .identity(identity_mock)
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        assert_eq!(
            AuthenticatedInfo::builder()
                .user_id("uid")
                .user(UserResponse {
                    id: "uid".to_string(),
                    domain_id: "user_domain_id".into(),
                    enabled: true,
                    ..Default::default()
                })
                .build()
                .unwrap(),
            authenticate_request(
                &state,
                &AuthRequest {
                    auth: AuthRequestInner {
                        identity: Identity {
                            methods: vec!["token".to_string()],
                            password: None,
                            token: Some(TokenAuth {
                                id: "fake_token".to_string()
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
    async fn test_authenticate_request_unsupported() {
        let config = Config::default();

        let provider = Provider::mocked_builder()
            .config(config.clone())
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                config,
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let rsp = authenticate_request(
            &state,
            &AuthRequest {
                auth: AuthRequestInner {
                    identity: Identity {
                        methods: vec!["fake".to_string()],
                        password: None,
                        token: None,
                    },
                    scope: None,
                },
            },
        )
        .await;
        if let KeystoneApiError::Unauthorized(..) = rsp.unwrap_err() {
        } else {
            panic!("Should receive Unauthorized");
        }
    }
}
