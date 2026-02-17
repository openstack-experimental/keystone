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
use crate::api::error::KeystoneApiError;
use crate::api::v3::auth::token::types::{System, Token, TokenBuilder, UserBuilder};
use crate::api::v3::role::types::Role;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::resource::{
    ResourceApi,
    types::{Domain, Project},
};
use crate::token::Token as ProviderToken;
use crate::trust::TrustApi;

use super::common::*;

impl Token {
    pub async fn from_provider_token(
        state: &ServiceState,
        token: &ProviderToken,
    ) -> Result<Token, KeystoneApiError> {
        let mut response = TokenBuilder::default();
        let mut project: Option<Project> = token.project().cloned();
        let mut domain: Option<Domain> = token.domain().cloned();
        response.audit_ids(token.audit_ids().clone());
        response.methods(token.methods().clone());
        response.expires_at(*token.expires_at());
        response.issued_at(*token.issued_at());

        let user = if let Some(user) = token.user() {
            user
        } else {
            &state
                .provider
                .get_identity_provider()
                .get_user(state, token.user_id())
                .await?
                .ok_or_else(|| KeystoneApiError::NotFound {
                    resource: "user".into(),
                    identifier: token.user_id().clone(),
                })?
        };

        let user_domain = common::get_domain(state, Some(&user.domain_id), None::<&str>).await?;

        let mut user_response: UserBuilder = UserBuilder::default();
        user_response.id(user.id.clone());
        user_response.name(user.name.clone());
        if let Some(val) = user.password_expires_at {
            user_response.password_expires_at(val);
        }
        user_response.domain(user_domain.clone());
        response.user(user_response.build()?);

        if let Some(roles) = token.roles() {
            response.roles(
                roles
                    .clone()
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<Role>>(),
            );
        }

        match token {
            ProviderToken::ApplicationCredential(token) => {
                if project.is_none() {
                    project = Some(
                        state
                            .provider
                            .get_resource_provider()
                            .get_project(state, &token.project_id)
                            .await?
                            .ok_or_else(|| KeystoneApiError::NotFound {
                                resource: "project".into(),
                                identifier: token.project_id.clone(),
                            })?,
                    );
                }
            }
            ProviderToken::DomainScope(token) => {
                if domain.is_none() {
                    domain = Some(
                        common::get_domain(state, Some(&token.domain_id), None::<&str>).await?,
                    );
                }
            }
            ProviderToken::FederationUnscoped(_token) => {}
            ProviderToken::FederationDomainScope(token) => {
                if domain.is_none() {
                    domain = Some(
                        common::get_domain(state, Some(&token.domain_id), None::<&str>).await?,
                    );
                }
            }
            ProviderToken::FederationProjectScope(token) => {
                if project.is_none() {
                    project = Some(
                        state
                            .provider
                            .get_resource_provider()
                            .get_project(state, &token.project_id)
                            .await?
                            .ok_or_else(|| KeystoneApiError::NotFound {
                                resource: "project".into(),
                                identifier: token.project_id.clone(),
                            })?,
                    );
                }
            }
            ProviderToken::ProjectScope(token) => {
                if project.is_none() {
                    project = Some(
                        state
                            .provider
                            .get_resource_provider()
                            .get_project(state, &token.project_id)
                            .await?
                            .ok_or_else(|| KeystoneApiError::NotFound {
                                resource: "project".into(),
                                identifier: token.project_id.clone(),
                            })?,
                    );
                }
            }
            ProviderToken::Restricted(token) => {
                if project.is_none() {
                    project = Some(
                        state
                            .provider
                            .get_resource_provider()
                            .get_project(state, &token.project_id)
                            .await?
                            .ok_or_else(|| KeystoneApiError::NotFound {
                                resource: "project".into(),
                                identifier: token.project_id.clone(),
                            })?,
                    );
                }
            }
            ProviderToken::SystemScope(_token) => {
                response.system(System { all: true });
            }
            ProviderToken::Trust(token) => {
                if project.is_none() {
                    project = Some(
                        state
                            .provider
                            .get_resource_provider()
                            .get_project(state, &token.project_id)
                            .await?
                            .ok_or_else(|| KeystoneApiError::NotFound {
                                resource: "project".into(),
                                identifier: token.project_id.clone(),
                            })?,
                    );
                }

                if let Some(trust) = &token.trust {
                    response.trust(trust);
                } else {
                    response.trust(
                        &state
                            .provider
                            .get_trust_provider()
                            .get_trust(state, &token.trust_id)
                            .await?
                            .ok_or_else(|| KeystoneApiError::NotFound {
                                resource: "trust".into(),
                                identifier: token.trust_id.clone(),
                            })?,
                    );
                }
            }
            ProviderToken::Unscoped(_token) => {}
        }

        if let Some(domain) = domain {
            response.domain(domain.clone());
        }
        if let Some(project) = project {
            response.project(
                get_project_info_builder(state, &project, &user_domain)
                    .await?
                    .build()?,
            );
        }
        Ok(response.build()?)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use crate::api::v3::auth::token::types::Token;
    use crate::api::v3::role::types::Role;
    use crate::role::types::Role as ProviderRole;

    use crate::config::Config;
    use crate::identity::{MockIdentityProvider, types::UserResponseBuilder};
    use crate::keystone::Service;
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;
    use crate::resource::{
        MockResourceProvider,
        types::{Domain, Project},
    };
    use crate::token::{
        DomainScopePayload, ProjectScopePayload, Token as ProviderToken, TrustPayload,
        UnscopedPayload,
    };
    use crate::trust::types::Trust;

    #[tokio::test]
    async fn test_from_unscoped() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });
        let provider = Provider::mocked_builder()
            .identity(identity_mock)
            .resource(resource_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let api_token = Token::from_provider_token(
            &state,
            &ProviderToken::Unscoped(UnscopedPayload {
                user_id: "bar".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!("bar", api_token.user.id);
        assert_eq!(Some("user_domain_id"), api_token.user.domain.id.as_deref());
        assert!(api_token.project.is_none());
        assert!(api_token.domain.is_none());
    }

    #[tokio::test]
    async fn test_from_domain_scoped() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .returning(|_, id: &'_ str| {
                Ok(Some(Domain {
                    id: id.to_string(),
                    ..Default::default()
                }))
            });
        let provider = Provider::mocked_builder()
            .identity(identity_mock)
            .resource(resource_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );

        let api_token = Token::from_provider_token(
            &state,
            &ProviderToken::DomainScope(DomainScopePayload {
                user_id: "bar".into(),
                domain_id: "domain_id".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        assert_eq!("bar", api_token.user.id);
        assert_eq!(Some("user_domain_id"), api_token.user.domain.id.as_deref());
        assert_eq!(
            Some("domain_id"),
            api_token.domain.expect("domain scope").id.as_deref()
        );
        assert!(api_token.project.is_none());
    }

    #[tokio::test]
    async fn test_from_project_scoped() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .returning(|_, id: &'_ str| {
                Ok(Some(Domain {
                    id: id.to_string(),
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_project()
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });
        let provider = Provider::mocked_builder()
            .identity(identity_mock)
            .resource(resource_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );
        let token = ProviderToken::ProjectScope(ProjectScopePayload {
            user_id: "bar".into(),
            project_id: "project_id".into(),
            roles: Some(vec![ProviderRole {
                id: "rid".into(),
                name: "role_name".into(),
                ..Default::default()
            }]),
            ..Default::default()
        });

        let api_token = Token::from_provider_token(&state, &token).await.unwrap();

        assert_eq!("bar", api_token.user.id);
        assert_eq!(Some("user_domain_id"), api_token.user.domain.id.as_deref());
        let project = api_token.project.expect("project_scope");
        assert_eq!(Some("project_domain_id"), project.domain.id.as_deref());
        assert_eq!("project_id", project.id);
        assert!(api_token.domain.is_none());
        assert_eq!(
            api_token.roles,
            Some(vec![Role {
                id: "rid".into(),
                name: "role_name".into(),
                ..Default::default()
            }])
        );
    }

    #[tokio::test]
    async fn test_from_trust() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("bar")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .returning(|_, id: &'_ str| {
                Ok(Some(Domain {
                    id: id.to_string(),
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_project()
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });
        let provider = Provider::mocked_builder()
            .identity(identity_mock)
            .resource(resource_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                MockPolicyFactory::new(),
            )
            .unwrap(),
        );
        let token = ProviderToken::Trust(TrustPayload {
            user_id: "bar".into(),
            methods: vec!["trust".into()],
            project_id: "project_id".into(),
            trust_id: "trust_id".into(),
            trust: Some(Trust {
                id: "trust_id".into(),
                impersonation: false,
                roles: Some(vec![ProviderRole {
                    id: "rid".into(),
                    name: "role_name".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        });

        let api_token = Token::from_provider_token(&state, &token).await.unwrap();

        assert_eq!("bar", api_token.user.id);
        assert_eq!(Some("user_domain_id"), api_token.user.domain.id.as_deref());
        let project = api_token.project.expect("project_scope");
        assert_eq!(Some("project_domain_id"), project.domain.id.as_deref());
        assert_eq!("project_id", project.id);
        assert!(api_token.domain.is_none());
        assert_eq!(
            api_token.roles,
            Some(vec![Role {
                id: "rid".into(),
                name: "role_name".into(),
                ..Default::default()
            }])
        );
    }
}
