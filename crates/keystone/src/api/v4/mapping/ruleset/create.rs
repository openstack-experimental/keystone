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
//! Mapping ruleset: create.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use openstack_keystone_api_types::v4::mapping::{
    MappingRuleSet, MappingRuleSetCreateRequest, MappingRuleSetResponse,
};
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create a new mapping ruleset.
#[utoipa::path(
    post,
    path = "/",
    operation_id = "/mapping_ruleset:create",
    request_body = MappingRuleSetCreateRequest,
    responses(
        (status = CREATED, description = "Ruleset object", body = MappingRuleSetResponse),
    ),
    security(("x-auth" = [])),
    tag="mapping_ruleset"
)]
#[tracing::instrument(
    name = "api::v4::mapping::ruleset::create",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<MappingRuleSetCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/mapping/ruleset/create",
            &user_auth,
            serde_json::json!({"mapping": req.mapping}),
            None,
        )
        .await?;

    let res = state
        .provider
        .get_mapping_provider()
        .create_ruleset(&ExecutionContext::from_auth(&state, &user_auth), req.into())
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(MappingRuleSetResponse {
            mapping: MappingRuleSet::from(res),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::mapping::{
        MappingRuleSetCreate, MappingRuleSetCreateRequest, MappingRuleSetResponse,
    };
    use openstack_keystone_core_types::mapping as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::mapping::MockMappingProvider;
    use crate::provider::Provider;

    fn sample_ruleset() -> MappingRuleSetCreate {
        MappingRuleSetCreate {
            mapping_id: Some("test-ruleset".into()),
            domain_id: Some("domain_id".into()),
            source: openstack_keystone_api_types::v4::mapping::IdentitySource::Federation {
                idp_id: "okta".into(),
            },
            domain_resolution_mode:
                openstack_keystone_api_types::v4::mapping::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![openstack_keystone_api_types::v4::mapping::MappingRule {
                name: "test-rule".into(),
                description: None,
                r#match: openstack_keystone_api_types::v4::mapping::MatchCriteria::AllOf(vec![
                    openstack_keystone_api_types::v4::mapping::MatchCondition::Condition(
                        openstack_keystone_api_types::v4::mapping::ClaimCondition::Equals {
                            claim: "test_claim".into(),
                            value: serde_json::json!("test_value"),
                        },
                    ),
                ]),
                identity: openstack_keystone_api_types::v4::mapping::IdentityBinding {
                    identity_mode: None,
                    user_name: "test_user".into(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: vec![],
                groups: vec![],
            }],
        }
    }

    fn sample_ruleset_core() -> provider_types::MappingRuleSet {
        provider_types::MappingRuleSet {
            mapping_id: "test-ruleset".into(),
            domain_id: Some("domain_id".into()),
            source: provider_types::IdentitySource::Federation {
                idp_id: "okta".into(),
            },
            domain_resolution_mode: provider_types::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![provider_types::MappingRule {
                name: "test-rule".into(),
                description: None,
                r#match: provider_types::MatchCriteria::AllOf(vec![
                    provider_types::MatchCondition::Condition(
                        provider_types::ClaimCondition::Equals {
                            claim: "test_claim".into(),
                            value: serde_json::json!("test_value"),
                        },
                    ),
                ]),
                identity: provider_types::IdentityBinding {
                    identity_mode: None,
                    user_name: "test_user".into(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: vec![],
                groups: vec![],
            }],
            ruleset_version: 1,
        }
    }

    #[tokio::test]
    async fn test_create() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockMappingProvider::default();
        mock.expect_create_ruleset()
            .returning(|_, _req| Ok(sample_ruleset_core()));
        provider = provider.mock_mapping(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = MappingRuleSetCreateRequest {
            mapping: sample_ruleset(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: MappingRuleSetResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.mapping.mapping_id, "test-ruleset");
    }

    #[tokio::test]
    async fn test_create_policy_denied() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = MappingRuleSetCreateRequest {
            mapping: sample_ruleset(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = MappingRuleSetCreateRequest {
            mapping: sample_ruleset(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Gate B3 (security review V3a, issue #979): drives this handler and
    /// the real `identity/mapping/ruleset/create.rego` decision (via a real
    /// `opa run` subprocess instead of `MockPolicy`) through the
    /// own-domain-manager/foreign-domain/global-requires-admin matrix.
    /// Requires `opa` on `PATH`.
    mod real_policy_decision {
        use openstack_keystone_core::auth::ValidatedSecurityContext;
        use openstack_keystone_core_types::auth::{
            AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
            SecurityContext, UserIdentityInfoBuilder,
        };
        use openstack_keystone_core_types::resource::Domain;
        use openstack_keystone_core_types::role::RoleRef;

        use super::*;
        use crate::api::tests::get_state_with_real_policy;
        use crate::provider::ProviderBuilder;

        fn domain_scoped_vsc(domain_id: &str, roles: &[&str]) -> ValidatedSecurityContext {
            let domain = Domain {
                id: domain_id.to_string(),
                name: domain_id.to_string(),
                enabled: true,
                ..Default::default()
            };

            let authz = AuthzInfoBuilder::default()
                .scope(ScopeInfo::Domain(domain.clone()))
                .roles(
                    roles
                        .iter()
                        .enumerate()
                        .map(|(i, name)| RoleRef {
                            domain_id: None,
                            id: format!("role-{i}"),
                            name: Some((*name).to_string()),
                        })
                        .collect::<Vec<_>>(),
                )
                .build()
                .unwrap();

            let sc = SecurityContext::test_build()
                .authentication_context(AuthenticationContext::Password)
                .principal(PrincipalInfo {
                    identity: IdentityInfo::User(
                        UserIdentityInfoBuilder::default()
                            .user_id("u1")
                            .user(
                                openstack_keystone_core_types::identity::UserResponseBuilder::default()
                                    .id("u1")
                                    .domain_id(domain_id)
                                    .enabled(true)
                                    .name("u1")
                                    .build()
                                    .unwrap(),
                            )
                            .user_domain(domain)
                            .build()
                            .unwrap(),
                    ),
                })
                .authorization(authz)
                .build();
            ValidatedSecurityContext::test_new(sc)
        }

        fn allowing_provider() -> ProviderBuilder {
            let mut mock = MockMappingProvider::default();
            mock.expect_create_ruleset()
                .returning(|_, _| Ok(sample_ruleset_core()));
            Provider::mocked_builder().mock_mapping(mock)
        }

        fn ruleset_for_domain(domain_id: Option<&str>) -> MappingRuleSetCreate {
            let mut ruleset = sample_ruleset();
            ruleset.domain_id = domain_id.map(String::from);
            ruleset
        }

        async fn create_request(
            vsc: ValidatedSecurityContext,
            domain_id: Option<&str>,
            provider_builder: ProviderBuilder,
        ) -> StatusCode {
            let (state, _opa_guard) = get_state_with_real_policy(provider_builder).await;
            let mut api = openapi_router()
                .layer(TraceLayer::new_for_http())
                .with_state(state);

            let req = MappingRuleSetCreateRequest {
                mapping: ruleset_for_domain(domain_id),
            };

            api.as_service()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/")
                        .header(header::CONTENT_TYPE, "application/json")
                        .extension(vsc)
                        .body(Body::from(serde_json::to_string(&req).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        #[tokio::test]
        async fn domain_manager_creating_ruleset_in_own_domain_is_allowed() {
            let status = create_request(
                domain_scoped_vsc("d1", &["manager"]),
                Some("d1"),
                allowing_provider(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }

        #[tokio::test]
        async fn domain_manager_creating_ruleset_in_foreign_domain_is_denied() {
            let status = create_request(
                domain_scoped_vsc("d1", &["manager"]),
                Some("d2"),
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn domain_manager_creating_global_ruleset_is_denied() {
            let status = create_request(
                domain_scoped_vsc("d1", &["manager"]),
                None,
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn admin_creating_global_ruleset_is_allowed() {
            let status = create_request(
                domain_scoped_vsc("d1", &["admin"]),
                None,
                allowing_provider(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }
    }
}
