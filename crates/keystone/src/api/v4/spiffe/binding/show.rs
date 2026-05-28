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

//! # SPIFFE binding: show.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::spiffe::binding::{SpiffeBinding, SpiffeBindingResponse};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::spiffe::SpiffeApi;

/// Get single SPIFFE binding.
///
/// Shows details of the existing SPIFFE binding by SVID.
#[utoipa::path(
    get,
    path = "/{svid}",
    operation_id = "/spiffe_binding:show",
    params(
      ("svid" = String, Path, description = "The SVID of the SPIFFE binding")
    ),
    responses(
        (status = OK, description = "Binding object", body = SpiffeBindingResponse),
        (status = 404, description = "Resource not found", example = json!(KeystoneApiError::NotFound(String::from("svid"))))
    ),
    security(("x-auth" = [])),
    tag="spiffe_binding"
)]
#[tracing::instrument(
    name = "api::v4::spiffe::binding::show",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(svid): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_spiffe_provider()
        .get_binding(&state, &svid)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "spiffe binding".into(),
            identifier: svid.clone(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/spiffe/binding/show",
            &user_auth,
            serde_json::json!({"binding": null}),
            Some(serde_json::to_value(&current)?),
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(SpiffeBindingResponse {
            binding: SpiffeBinding::from(current),
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

    use openstack_keystone_core_types::spiffe as provider_types;

    use super::{super::openapi_router, *};
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::provider::Provider;
    use crate::spiffe::MockSpiffeProvider;

    #[tokio::test]
    async fn test_show() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockSpiffeProvider::default();
        mock.expect_get_binding()
            .withf(|_, svid: &'_ str| svid == "spiffe://example.com/foo")
            .returning(|_, _| {
                Ok(Some(provider_types::SpiffeBinding {
                    authorizations: None,
                    domain_id: "did".into(),
                    svid: "spiffe://example.com/foo".into(),
                    is_system: false,
                    user_id: Some("uid".into()),
                }))
            });
        mock.expect_get_binding()
            .withf(|_, svid: &'_ str| svid != "spiffe://example.com/foo")
            .returning(|_, _| Ok(None));
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/spiffe%3A%2F%2Fexample.com%2Ffoo")
                    .extension(vsc.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.binding.svid, "spiffe://example.com/foo");
    }

    #[tokio::test]
    async fn test_show_not_found() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockSpiffeProvider::default();
        mock.expect_get_binding().returning(|_, _| Ok(None));
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/spiffe://example.com/missing")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
