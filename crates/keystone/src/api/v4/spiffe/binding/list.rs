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
//! # SPIFFE binding: list.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::spiffe::binding::{
    SpiffeBinding, SpiffeBindingList, SpiffeBindingListParameters,
};
use openstack_keystone_core_types::spiffe::SpiffeBindingListParameters as ProviderSpiffeBindingListParameters;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::spiffe::SpiffeApi;

/// List SPIFFE bindings.
///
/// List existing SPIFFE bindings.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/spiffe_binding:list",
    params(SpiffeBindingListParameters),
    responses(
        (status = OK, description = "List of SPIFFE bindings.", body = SpiffeBindingList),
    ),
    security(("x-auth" = [])),
    tag="spiffe_binding"
)]
#[tracing::instrument(
    name = "api::v4::spiffe::binding::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Query(query): Query<SpiffeBindingListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/spiffe/binding/list",
            &user_auth,
            serde_json::json!({"binding": query}),
            None,
        )
        .await?;

    let provider_list_params: ProviderSpiffeBindingListParameters = query.into();

    let bindings: Vec<SpiffeBinding> = state
        .provider
        .get_spiffe_provider()
        .list_bindings(&state, &provider_list_params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    Ok((
        StatusCode::OK,
        Json(SpiffeBindingList {
            bindings,
            links: None,
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
    async fn test_list() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockSpiffeProvider::default();
        mock.expect_list_bindings().returning(|_, _| {
            Ok(vec![provider_types::SpiffeBinding {
                authorizations: None,
                domain_id: "did".into(),
                svid: "spiffe://example.com/foo".into(),
                is_system: false,
                user_id: Some("uid".into()),
            }])
        });
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.bindings.len(), 1);
        assert_eq!(res.bindings[0].svid, "spiffe://example.com/foo");
    }

    #[tokio::test]
    async fn test_list_domain_filter() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockSpiffeProvider::default();
        mock.expect_list_bindings()
            .withf(|_, params: &provider_types::SpiffeBindingListParameters| {
                params.domain_id == Some("did".into())
            })
            .returning(|_, _| Ok(vec![]));
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=did")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingList = serde_json::from_slice(&body).unwrap();
        assert!(res.bindings.is_empty());
    }
}
