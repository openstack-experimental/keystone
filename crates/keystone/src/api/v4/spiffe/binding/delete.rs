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

//! # SPIFFE binding: delete.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::spiffe::SpiffeApi;

/// Delete SPIFFE binding.
///
/// Deletes the existing SPIFFE binding by SVID.
#[utoipa::path(
    delete,
    path = "/{svid}",
    operation_id = "/spiffe_binding:delete",
    params(
      ("svid" = String, Path, description = "The SVID of the binding to delete")
    ),
    responses(
        (status = 204, description = "Deleted."),
        (status = 404, description = "Binding not found", example = json!(KeystoneApiError::NotFound(String::from("svid"))))
    ),
    security(("x-auth" = [])),
    tag="spiffe_binding"
)]
#[tracing::instrument(
    name = "api::v4::spiffe::binding::delete",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn remove(
    Auth(user_auth): Auth,
    Path(svid): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_spiffe_provider()
        .get_binding(&state, &svid)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/spiffe/binding/delete",
            &user_auth,
            serde_json::json!({"binding": null}),
            current.as_ref().map(serde_json::to_value).transpose()?,
        )
        .await?;

    if current.is_some() {
        state
            .provider
            .get_spiffe_provider()
            .delete_binding(&state, &svid)
            .await?;
    } else {
        return Err(KeystoneApiError::NotFound {
            resource: "spiffe binding".to_string(),
            identifier: svid.clone(),
        });
    }

    Ok((StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::spiffe as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::provider::Provider;
    use crate::spiffe::MockSpiffeProvider;

    #[tokio::test]
    async fn test_delete() {
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

        mock.expect_delete_binding()
            .withf(|_, svid: &'_ str| svid == "spiffe://example.com/foo")
            .returning(|_, _| Ok(()));

        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/spiffe%3A%2F%2Fexample.com%2Ffoo")
                    .extension(vsc.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_not_found() {
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
                    .method("DELETE")
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
