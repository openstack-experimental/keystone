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

//! Federation attribute mapping: create.
use axum::{Json, debug_handler, extract::State, http::StatusCode, response::IntoResponse};
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::federation::{FederationApi, api::types::*};
use crate::keystone::ServiceState;

/// Create attribute mapping.
#[utoipa::path(
    post,
    path = "/",
    operation_id = "/federation/mapping:create",
    responses(
        (status = CREATED, description = "mapping object", body = MappingResponse),
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(name = "api::mapping_create", level = "debug", skip(state, user_auth))]
#[debug_handler]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<MappingCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    state
        .policy_enforcer
        .enforce(
            "identity/mapping_create",
            &user_auth,
            serde_json::to_value(&req.mapping)?,
            None,
        )
        .await?;

    let res = state
        .provider
        .get_federation_provider()
        .create_mapping(&state, req.into())
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(MappingResponse {
            mapping: Mapping::from(res),
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
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use openstack_keystone_core_types::federation as provider_types;

    use super::{super::openapi_router, *};
    use crate::api::tests::get_mocked_state;
    use crate::federation::MockFederationProvider;
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_create() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_create_mapping()
            .withf(|_, req: &provider_types::Mapping| req.name == "name")
            .returning(|_, _| {
                Ok(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                })
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_federation(federation_mock),
            true,
            None,
            None,
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = MappingCreateRequest {
            mapping: MappingCreate {
                name: "name".into(),
                domain_id: Some("did".into()),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: MappingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.mapping.name, req.mapping.name);
        assert_eq!(res.mapping.domain_id, req.mapping.domain_id);
    }
}
