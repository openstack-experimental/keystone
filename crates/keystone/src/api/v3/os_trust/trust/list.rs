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

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::{Trust, TrustList, TrustListParameters};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::policy::PolicyError;

/// List trusts.
///
/// Two-phase policy check (I8, CVE-2019-19687 class): the collection-level
/// `identity/trust/list` policy is enforced first against the filter hints,
/// then every returned trust is individually re-checked against
/// `identity/trust/show` using that record's own trustor/trustee identity,
/// dropping any the caller may not read -- authorization here depends on
/// per-item identity, not a uniform collection-level rule.
#[utoipa::path(
    get,
    path = "/",
    params(TrustListParameters),
    description = "List trusts",
    responses(
        (status = OK, description = "List of trusts", body = TrustList),
        (status = 500, description = "Internal error")
    ),
    tag="OS-TRUST"
)]
#[tracing::instrument(name = "api::trust_list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Query(query): Query<TrustListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/trust/list",
            &user_auth,
            json!({"trust": query}),
            None,
        )
        .await?;

    let raw = state
        .provider
        .get_trust_provider()
        .list_trusts(
            &ExecutionContext::from_auth(&state, &user_auth),
            &query.into(),
        )
        .await?;

    let mut trusts = Vec::with_capacity(raw.len());
    for item in raw {
        match state
            .policy_enforcer
            .enforce(
                "identity/trust/show",
                &user_auth,
                serde_json::Value::Null,
                Some(json!({"trust": item})),
            )
            .await
        {
            Ok(_) => trusts.push(Trust::from(item)),
            Err(PolicyError::Forbidden(_)) => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Ok((StatusCode::OK, Json(TrustList { trusts })).into_response())
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

    use openstack_keystone_core_types::trust::{TrustBuilder, TrustListParameters};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::os_trust::trust::types::TrustList;
    use crate::provider::Provider;
    use crate::trust::MockTrustProvider;

    #[tokio::test]
    async fn test_list() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock
            .expect_list_trusts()
            .withf(|_, _: &TrustListParameters| true)
            .returning(|_, _| {
                Ok(vec![
                    TrustBuilder::default()
                        .id("1")
                        .trustor_user_id("trustor")
                        .trustee_user_id("trustee")
                        .impersonation(false)
                        .build()
                        .unwrap(),
                ])
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_trust(trust_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

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
        let res: TrustList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.trusts.len(), 1);
        assert_eq!(res.trusts[0].id, "1");
    }

    #[tokio::test]
    async fn test_list_collection_denied_drops_all_items() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock.expect_list_trusts().returning(|_, _| {
            Ok(vec![
                TrustBuilder::default()
                    .id("1")
                    .trustor_user_id("trustor")
                    .trustee_user_id("trustee")
                    .impersonation(false)
                    .build()
                    .unwrap(),
            ])
        });

        let vsc = test_fixture_scoped();
        // policy_allow = false: the initial list-level check is rejected,
        // so the handler must not reach the per-item loop.
        let state = get_mocked_state(
            Provider::mocked_builder().mock_trust(trust_mock),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
