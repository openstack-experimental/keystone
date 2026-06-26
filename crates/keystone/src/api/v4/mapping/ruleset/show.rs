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
//! Mapping ruleset: show.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::mapping::{MappingRuleSet, MappingRuleSetResponse};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Show a mapping ruleset by ID.
#[utoipa::path(
    get,
    path = "/{mapping_id}",
    operation_id = "/mapping_ruleset:show",
    params(
        ("mapping_id" = String, Path, description = "Mapping ruleset ID"),
    ),
    responses(
        (status = OK, description = "Ruleset object", body = MappingRuleSetResponse),
    ),
    security(("x-auth" = [])),
    tag="mapping_ruleset"
)]
#[tracing::instrument(
    name = "api::v4::mapping::ruleset::show",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(mapping_id): Path<String>,
    State(state): State<ServiceState>,
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
            "identity/mapping/ruleset/show",
            &user_auth,
            serde_json::json!({"mapping": null}),
            Some(serde_json::json!({"mapping": MappingRuleSet::from(current.clone())})),
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(MappingRuleSetResponse {
            mapping: MappingRuleSet::from(current),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::mapping::MappingRuleSetResponse;
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
    async fn test_show() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockMappingProvider::default();
        mock.expect_get_ruleset()
            .returning(|_, _| Ok(Some(sample_ruleset_core())));
        provider = provider.mock_mapping(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/test-ruleset")
                    .extension(vsc)
                    .body(Body::empty())
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
    async fn test_show_policy_denied() {
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

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/test-ruleset")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_show_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/test-ruleset")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
