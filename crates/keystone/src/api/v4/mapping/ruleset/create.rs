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
        .create_ruleset(&state, req.into())
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
}
