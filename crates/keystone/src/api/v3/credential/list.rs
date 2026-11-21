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
use crate::api::common::{
    AuthorizedPage, collect_authorized_page, paginate_forward_filtered, with_self_link,
};
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
///
/// The first phase is what keeps the second one cheap: unless the caller is
/// a privileged lister (`admin`, or `reader` on the system scope),
/// `identity/credential/list` demands a `user_id` filter naming the caller
/// (issue #1117), so the driver narrows the query in SQL rather than
/// handing the whole table to the per-item loop. The filter the policy
/// approves and the filter the driver applies are the *same* value — both
/// read `CredentialListParameters::user_id` off this one parsed struct — so
/// the two cannot diverge.
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
    let base_params =
        openstack_keystone_core_types::credential::CredentialListParameters::from(query);
    let limit = config.resolve_list_limit(&config.credential.list_limit, pagination.limit);

    // Bind by reference: `collect_authorized_page` takes `FnMut`, so the
    // per-batch future must capture a `Copy` handle rather than move the
    // context out of the closure.
    let provider = state.provider.get_credential_provider();
    let exec_ctx = ExecutionContext::from_auth(&state, &user_auth);
    let exec = &exec_ctx;
    let enforcer = &state.policy_enforcer;
    let auth = &user_auth;

    let page = collect_authorized_page(
        limit,
        pagination.marker.clone(),
        |marker| {
            let mut params = base_params.clone();
            params.pagination = ListPagination {
                limit,
                marker,
                page_reverse: false,
            };
            async move { Ok(provider.list_credentials(exec, &params).await?) }
        },
        |item: openstack_keystone_core_types::credential::Credential| async move {
            match enforcer
                .enforce(
                    "identity/credential/show",
                    auth,
                    serde_json::Value::Null,
                    Some(super::credential_policy_input(&item)),
                )
                .await
            {
                Ok(_) => Ok(Some(item)),
                Err(PolicyError::Forbidden(_)) => Ok(None),
                Err(err) => Err(err.into()),
            }
        },
    )
    .await?;
    let page = AuthorizedPage {
        items: page
            .items
            .into_iter()
            .map(|x| with_self_link(Credential::from(x), &original_url))
            .collect::<Vec<Credential>>(),
        scan_budget_exhausted: page.scan_budget_exhausted,
    };

    let (credentials, links) = paginate_forward_filtered(
        &config,
        &config.credential.list_limit,
        page,
        &pagination,
        &original_url,
    )?;

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
    /// has no resource project to anchor on, so it admits a delegated
    /// caller filtering to their own `user_id` and leaves the project
    /// boundary entirely to the re-check. This drives such a caller's list
    /// through the real `identity/credential/show.rego` decision (via a
    /// real `opa run` subprocess) over a mixed batch: one record bound to
    /// the delegation's own project (must survive), one bound to a
    /// different project, and one unscoped (both must be silently dropped,
    /// never surfaced as an error). Requires `opa` on `PATH`.
    ///
    /// The `?user_id=u1` filter is load-bearing since issue #1117: the
    /// caller holds only `member`, so an unfiltered list is now denied
    /// outright by the collection-level check and would never reach the
    /// per-item pass this test exists to exercise.
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
                    .uri("/?user_id=u1")
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

    /// Issue #1117, the negative case that is the whole point of the change:
    /// an ordinary `member` may no longer scan the collection. Driven
    /// through a real `opa run` subprocess, because the mocked enforcer used
    /// by the tests above answers `allow` unconditionally and so cannot
    /// distinguish the old rule from the new one.
    ///
    /// The backend mock deliberately sets no expectation for
    /// `list_credentials`: the collection-level denial must short-circuit
    /// *before* any row is fetched, so `mockall` fails the test if the
    /// handler reaches the driver at all. That is the DoS property under
    /// test -- a 403 that still scanned the table would fix nothing.
    #[tokio::test]
    async fn unfiltered_list_by_ordinary_member_is_denied_by_real_policy() {
        let credential_mock = MockCredentialProvider::default();

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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Issue #1117, the happy path the restriction must leave intact: an
    /// ordinary, non-delegated `member` filtering to their own `user_id`
    /// still gets their credentials back, and the filter reaches the driver
    /// so the query is narrowed in SQL rather than in the per-item loop.
    #[tokio::test]
    async fn own_filtered_list_by_ordinary_member_is_allowed_by_real_policy() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials()
            .withf(|_, qp: &CredentialListParameters| qp.user_id.as_deref() == Some("u1"))
            .returning(|_, _| {
                Ok(vec![
                    CredentialBuilder::default()
                        .id("own")
                        .blob(r#"{"seed":"AAAA"}"#)
                        .r#type("totp")
                        .user_id("u1")
                        .build()
                        .unwrap(),
                ])
            });

        let vsc = crate::api::tests::real_policy_fixtures::member_vsc("u1", "p1", &["member"]);
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
                    .uri("/?user_id=u1")
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
            vec!["own"]
        );
    }

    /// Issue #1117 must not cost the privileged listers their cross-user
    /// view: a system-scoped `reader` still lists the collection unfiltered.
    #[tokio::test]
    async fn unfiltered_list_by_system_reader_is_allowed_by_real_policy() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock.expect_list_credentials().returning(|_, _| {
            Ok(vec![
                CredentialBuilder::default()
                    .id("someone-elses")
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("u2")
                    .build()
                    .unwrap(),
            ])
        });

        let vsc =
            crate::api::tests::real_policy_fixtures::system_scoped_vsc("u1", "all", &["reader"]);
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
            vec!["someone-elses"]
        );
    }

    /// Issue #1117: naming somebody else's `user_id` must not buy the scan
    /// either -- otherwise the filter would be a formality rather than a
    /// boundary. As above, the driver must never be reached.
    #[tokio::test]
    async fn list_filtered_to_another_user_is_denied_by_real_policy() {
        let credential_mock = MockCredentialProvider::default();

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
                    .uri("/?user_id=u2")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
