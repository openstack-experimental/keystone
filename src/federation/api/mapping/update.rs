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

//! Federation attribute mapping: update
use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use mockall_double::double;
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::federation::{FederationApi, api::types::*};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Update attribute mapping.
///
/// TODO: describe domain_id update rules
#[utoipa::path(
    put,
    path = "/{id}",
    operation_id = "/federation/mapping:update",
    params(
      ("id" = String, Path, description = "The ID of the attribute mapping.")
    ),
    responses(
        (status = OK, description = "mapping object", body = MappingResponse),
        (status = 404, description = "mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_update",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<MappingUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let current = state
        .provider
        .get_federation_provider()
        .get_mapping(&state, &id)
        .await?;

    policy
        .enforce(
            "identity/mapping_update",
            &user_auth,
            serde_json::to_value(&current)?,
            Some(serde_json::to_value(&req.mapping)?),
        )
        .await?;

    let res = state
        .provider
        .get_federation_provider()
        .update_mapping(&state, &id, req.into())
        .await?;
    Ok(res.into_response())
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

    use super::{
        super::{openapi_router, tests::get_mocked_state},
        *,
    };
    use crate::federation::{MockFederationProvider, types as provider_types};

    #[tokio::test]
    #[traced_test]
    async fn test_update() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_mapping()
            .withf(|_, id: &'_ str| id == "1")
            .returning(|_, _| {
                Ok(Some(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }))
            });

        federation_mock
            .expect_update_mapping()
            .withf(|_, id: &'_ str, req: &provider_types::MappingUpdate| {
                id == "1" && req.name == Some("name".to_string())
            })
            .returning(|_, _, _| {
                Ok(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                })
            });

        let state = get_mocked_state(federation_mock, true);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = MappingUpdateRequest {
            mapping: MappingUpdate {
                name: Some("name".into()),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/1")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: MappingResponse = serde_json::from_slice(&body).unwrap();
    }
}
