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

//! Identity providers: show IDP
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use mockall_double::double;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v4::federation::types::*;
use crate::federation::FederationApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Get single identity provider.
///
/// Shows details of the existing identity provider.
#[utoipa::path(
    get,
    path = "/{idp_id}",
    operation_id = "/federation/identity_provider:show",
    params(
      ("idp_id" = String, Path, description = "The ID of the identity provider")
    ),
    responses(
        (status = OK, description = "Identity provider object", body = IdentityProviderResponse),
        (status = 404, description = "Resource not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_get",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(idp_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id,
            })
        })??;

    policy
        .enforce(
            "identity/identity_provider_show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    Ok(current)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
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
    async fn test_get() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_identity_provider()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        federation_mock
            .expect_get_identity_provider()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::IdentityProvider {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    enabled: true,
                    default_mapping_name: Some("dummy".into()),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(federation_mock, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: IdentityProviderResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            IdentityProvider {
                id: "bar".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                enabled: true,
                oidc_discovery_url: None,
                oidc_client_id: None,
                oidc_response_mode: None,
                oidc_response_types: None,
                jwks_url: None,
                jwt_validation_pubkeys: None,
                bound_issuer: None,
                default_mapping_name: Some("dummy".into()),
                provider_config: None
            },
            res.identity_provider,
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_get_forbidden() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_identity_provider()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::IdentityProvider {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    default_mapping_name: Some("dummy".into()),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(federation_mock, false, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
