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
//! Mapping ruleset: mutate rules.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::v4::mapping::{
    MappingRuleSet, MappingRuleSetResponse, RuleMutationsRequest,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Mutate rules within a mapping ruleset imperatively.
///
/// Allows insertion, update, and deletion of individual rules
/// at specific positions within the ruleset.
#[utoipa::path(
    post,
    path = "/{mapping_id}/rules/mutate",
    operation_id = "/mapping_ruleset:rules_mutate",
    params(
        ("mapping_id" = String, Path, description = "Mapping ruleset ID"),
    ),
    request_body = RuleMutationsRequest,
    responses(
        (status = OK, description = "Ruleset object", body = MappingRuleSetResponse),
    ),
    security(("x-auth" = [])),
    tag="mapping_ruleset"
)]
#[tracing::instrument(
    name = "api::v4::mapping::ruleset::mutate",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn mutate(
    Auth(user_auth): Auth,
    Path(mapping_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<RuleMutationsRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_mapping_provider()
        .get_ruleset(
            &ExecutionContext::from_auth(&state, &user_auth),
            &mapping_id,
        )
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "mapping ruleset".into(),
            identifier: mapping_id.clone(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/mapping/ruleset/update",
            &user_auth,
            json!({"mapping": req}),
            Some(json!({"mapping": MappingRuleSet::from(current)})),
        )
        .await?;

    let res = state
        .provider
        .get_mapping_provider()
        .mutate_rules(
            &ExecutionContext::from_auth(&state, &user_auth),
            &mapping_id,
            req.into(),
        )
        .await?;

    Ok((
        StatusCode::OK,
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

    use openstack_keystone_api_types::v4::mapping::{MappingRuleSetResponse, RuleMutationsRequest};
    use openstack_keystone_core_types::mapping as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::mapping::MockMappingProvider;
    use crate::provider::Provider;

    fn sample_ruleset_core() -> provider_types::MappingRuleSet {
        provider_types::MappingRuleSet {
            mapping_id: "test-ruleset".into(),
            domain_id: Some("domain_id".into()),
            source: provider_types::IdentitySource::Federation {
                idp_id: "okta".into(),
            },
            domain_resolution_mode: provider_types::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![],
            ruleset_version: 1,
        }
    }

    #[tokio::test]
    async fn test_mutate() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockMappingProvider::default();
        mock.expect_get_ruleset()
            .returning(|_, _| Ok(Some(sample_ruleset_core())));
        mock.expect_mutate_rules()
            .returning(|_, _, _| Ok(sample_ruleset_core()));
        provider = provider.mock_mapping(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = RuleMutationsRequest { mutations: vec![] };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/test-ruleset/rules/mutate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: MappingRuleSetResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.mapping.mapping_id, "test-ruleset");
    }

    #[tokio::test]
    async fn test_mutate_policy_denied() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockMappingProvider::default();
        mock.expect_get_ruleset()
            .returning(|_, _| Ok(Some(sample_ruleset_core())));
        provider = provider.mock_mapping(mock);

        let state = get_mocked_state(provider, false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = RuleMutationsRequest { mutations: vec![] };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/test-ruleset/rules/mutate")
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
    async fn test_mutate_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_mapping(MockMappingProvider::default()),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = RuleMutationsRequest { mutations: vec![] };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/test-ruleset/rules/mutate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
