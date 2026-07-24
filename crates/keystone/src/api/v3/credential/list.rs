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
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core_types::ListPagination;

use super::types::{Credential, CredentialList, CredentialListParameters};
use crate::api::auth::Auth;
use crate::api::common::paginate_forward;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::policy::PolicyError;

/// List credentials.
///
/// Two-phase policy check (ADR 0019 §2, CVE-2019-19687): first
/// `identity/credential/list` is enforced against the driver-level filter
/// hints, then every returned record is individually re-checked against
/// `identity/credential/show` using *that record's own* `user_id`/
/// `project_id` as the policy target, dropping any the caller may not read.
/// Pagination is applied *after* this per-item filtering, over the
/// already-policy-approved set, matching the over-fetch-by-one convention
/// used everywhere else.
#[utoipa::path(
    get,
    path = "/",
    params(CredentialListParameters, PaginationQuery),
    description = "List credentials",
    responses(
        (status = OK, description = "List of credentials", body = CredentialList),
        (status = 500, description = "Internal error")
    ),
    tag="credentials"
)]
#[tracing::instrument(name = "api::credential_list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<CredentialListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/credential/list",
            &user_auth,
            json!({"credential": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let mut provider_params =
        openstack_keystone_core_types::credential::CredentialListParameters::from(query);
    provider_params.pagination = ListPagination {
        limit: config.resolve_list_limit(&config.credential.list_limit, pagination.limit),
        marker: pagination.marker.clone(),
        page_reverse: false,
    };

    let raw = state
        .provider
        .get_credential_provider()
        .list_credentials(
            &ExecutionContext::from_auth(&state, &user_auth),
            &provider_params,
        )
        .await?;

    let mut credentials = Vec::with_capacity(raw.len());
    for item in raw {
        match state
            .policy_enforcer
            .enforce(
                "identity/credential/show",
                &user_auth,
                serde_json::Value::Null,
                Some(super::credential_policy_input(&item)),
            )
            .await
        {
            Ok(_) => credentials.push(Credential::from(item)),
            Err(PolicyError::Forbidden(_)) => continue,
            Err(err) => return Err(err.into()),
        }
    }

    let (credentials, links) =
        paginate_forward(&config, credentials, &pagination, original_url.path())?;

    Ok((StatusCode::OK, Json(CredentialList { credentials, links })).into_response())
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

    use openstack_keystone_core_types::credential::{CredentialBuilder, CredentialListParameters};

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::api::v3::credential::types::CredentialList;
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    /// Gate B2 (issue #978): list performs a two-phase check (ADR 0019 §2,
    /// CVE-2019-19687) -- assert *both* calls: the list-level filter-hint
    /// check and the per-item `identity/credential/show` re-check, with the
    /// per-item call keying the stripped stored record under `existing`.
    #[tokio::test]
    async fn test_list_policy_input_contract() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock.expect_list_credentials().returning(|_, _| {
            Ok(vec![
                CredentialBuilder::default()
                    .id("1")
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ])
        });

        let vsc = test_fixture_scoped();
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_credential(credential_mock)).await;

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

        let calls = policy.calls();
        assert_eq!(calls.len(), 2);

        assert_eq!(calls[0].policy_name, "identity/credential/list");
        policy_contract::assert_object_keys(&calls[0].target, &["credential"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        policy_contract::assert_no_secrets(&calls[0].target);

        assert_eq!(calls[1].policy_name, "identity/credential/show");
        assert_eq!(calls[1].target, serde_json::Value::Null);
        policy_contract::assert_existing_presence(&calls[1].existing, true);
        let existing = calls[1].existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["credential"]);
        policy_contract::assert_no_secrets(existing);
    }

    #[tokio::test]
    async fn test_list() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials()
            .withf(|_, _: &CredentialListParameters| true)
            .returning(|_, _| {
                Ok(vec![
                    CredentialBuilder::default()
                        .id("1")
                        .blob(r#"{"seed":"AAAA"}"#)
                        .r#type("totp")
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ])
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_credential(credential_mock),
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
        let res: CredentialList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.credentials.len(), 1);
        assert_eq!(res.credentials[0].id, "1");
    }

    #[tokio::test]
    async fn test_list_denied_drops_all_items() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock.expect_list_credentials().returning(|_, _| {
            Ok(vec![
                CredentialBuilder::default()
                    .id("1")
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("someone-else")
                    .build()
                    .unwrap(),
            ])
        });

        let vsc = test_fixture_scoped();
        // policy_allow = false: the initial list-level check itself is
        // rejected, so the handler must not reach the per-item loop.
        let state = get_mocked_state(
            Provider::mocked_builder().mock_credential(credential_mock),
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

    /// Gate B3 (security review V3a, issue #979): the per-item re-check
    /// (ADR 0019 §2, CVE-2019-19687) is where `list`'s delegation boundary
    /// (OSSA-2026-015) actually lives -- `identity/credential/list.rego`
    /// itself lets any member attempt to list, so this drives a delegated
    /// caller's list through the real `identity/credential/show.rego`
    /// decision (via a real `opa run` subprocess) over a mixed batch: one
    /// record bound to the delegation's own project (must survive), one
    /// bound to a different project, and one unscoped (both must be
    /// silently dropped, never surfaced as an error). Requires `opa` on
    /// `PATH`.
    #[tokio::test]
    async fn delegated_caller_list_is_filtered_to_own_project_by_real_policy() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock.expect_list_credentials().returning(|_, _| {
            Ok(vec![
                CredentialBuilder::default()
                    .id("own-project")
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("u1")
                    .project_id("p1")
                    .build()
                    .unwrap(),
                CredentialBuilder::default()
                    .id("other-project")
                    .blob(r#"{"seed":"BBBB"}"#)
                    .r#type("totp")
                    .user_id("u1")
                    .project_id("p2")
                    .build()
                    .unwrap(),
                CredentialBuilder::default()
                    .id("unscoped")
                    .blob(r#"{"seed":"CCCC"}"#)
                    .r#type("totp")
                    .user_id("u1")
                    .build()
                    .unwrap(),
            ])
        });

        let vsc = crate::api::tests::real_policy_fixtures::restricted_app_cred_vsc("u1", "p1");
        let (state, _opa_guard) = crate::api::tests::get_state_with_real_policy(
            Provider::mocked_builder().mock_credential(credential_mock),
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
        let res: CredentialList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            res.credentials
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            vec!["own-project"]
        );
    }

    /// Backend over-fetched (returned `limit + 1 == 2` rows): a `next` link
    /// is produced and the extra row trimmed from the response body.
    #[tokio::test]
    async fn test_list_pagination_link() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials()
            .withf(|_, qp: &CredentialListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| {
                Ok(vec![
                    CredentialBuilder::default()
                        .id("1")
                        .blob(r#"{"seed":"AAAA"}"#)
                        .r#type("totp")
                        .user_id("uid")
                        .build()
                        .unwrap(),
                    CredentialBuilder::default()
                        .id("2")
                        .blob(r#"{"seed":"BBBB"}"#)
                        .r#type("totp")
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ])
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_credential(credential_mock),
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
                    .uri("/?limit=1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: CredentialList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.credentials.len(), 1);
        assert_eq!(res.credentials[0].id, "1");
        assert!(res.links.is_some());
    }

    /// Backend returned exactly `limit` rows (no over-fetched extra row): no
    /// `next` link should be produced.
    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials()
            .withf(|_, qp: &CredentialListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| {
                Ok(vec![
                    CredentialBuilder::default()
                        .id("1")
                        .blob(r#"{"seed":"AAAA"}"#)
                        .r#type("totp")
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ])
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_credential(credential_mock),
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
                    .uri("/?limit=1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: CredentialList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.credentials.len(), 1);
        assert_eq!(res.links, None);
    }
}
