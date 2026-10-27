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

use axum::{
    Json,
    extract::{OriginalUri, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::policy::PolicyError;
use openstack_keystone_core_types::ListPagination;

use crate::api::auth::Auth;
use crate::api::common::{collect_authorized_page, paginate_forward_filtered};
use crate::api::error::KeystoneApiError;
use crate::api::v3::user::types::{User, UserList, UserListParameters};
use crate::keystone::ServiceState;

/// List users in a group.
///
/// Two-phase policy check (security model I8): `identity/group/user/list` is
/// enforced against the group first, then **every** returned user is
/// individually re-checked against `identity/user/show`, dropping the ones the
/// caller may not read.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/groups/group_id/users:list",
    params(
        ("group_id" = String, Path, description = "The group ID."),
        UserListParameters,
        PaginationQuery
    ),
    responses(
        (status = OK, description = "List of users in the group", body = UserList),
        (status = 404, description = "Group not found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    security(("x-auth" = [])),
    tag = "groups"
)]
#[tracing::instrument(name = "api::group_user_list", level = "debug", skip(state, user_auth))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Path(group_id): Path<String>,
    Query(query): Query<UserListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    query.validate()?;
    let exec_ctx = ExecutionContext::from_auth(&state, &user_auth);
    let group = state
        .provider
        .get_identity_provider()
        .get_group(&exec_ctx, &group_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/group/user/list",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"group": group})),
        )
        .await?;
    if group.is_none() {
        return Err(KeystoneApiError::NotFound {
            resource: "group".into(),
            identifier: group_id,
        });
    }

    let config = state.config_manager.config.read().await;
    let mut base_params = openstack_keystone_core_types::identity::UserListParameters::from(query);
    base_params.group_id = Some(group_id);
    let limit = config.resolve_list_limit(&config.identity.list_limit, pagination.limit);

    let identity = state.provider.get_identity_provider();
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
            async move {
                Ok(identity
                    .list_users(exec, &params)
                    .await?
                    .into_iter()
                    .map(User::from)
                    .collect())
            }
        },
        |item: User| async move {
            match enforcer
                .enforce(
                    "identity/user/show",
                    auth,
                    serde_json::Value::Null,
                    Some(json!({"user": &item})),
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

    let (users, links) = paginate_forward_filtered(
        &config,
        &config.identity.list_limit,
        page,
        &pagination,
        &original_url,
    )?;

    Ok((StatusCode::OK, Json(UserList { users, links })).into_response())
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

    use openstack_keystone_core::policy::{PolicyError, PolicyEvaluationResult};
    use openstack_keystone_core_types::identity::{
        Group, UserListParameters, UserResponse, UserResponseBuilder,
    };

    use super::super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, get_state_with_mock_policy, policy_contract,
        test_fixture_scoped,
    };
    use crate::api::v3::user::types::UserList;
    use crate::identity::MockIdentityProvider;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;

    fn user(id: &str, domain_id: &str) -> UserResponse {
        UserResponseBuilder::default()
            .id(id)
            .domain_id(domain_id)
            .enabled(true)
            .name(id)
            .build()
            .unwrap()
    }

    fn identity(group_found: bool, users: Vec<UserResponse>) -> MockIdentityProvider {
        let mut mock = MockIdentityProvider::default();
        mock.expect_get_group().returning(move |_, _| {
            Ok(group_found.then(|| Group {
                id: "g".into(),
                name: "group".into(),
                domain_id: "did".into(),
                ..Default::default()
            }))
        });
        mock.expect_list_users()
            .withf(|_, qp: &UserListParameters| qp.group_id.as_deref() == Some("g"))
            .returning(move |_, _| Ok(users.clone()));
        mock
    }

    fn request(authenticated: bool) -> Request<Body> {
        let mut req = Request::builder().uri("/g/users");
        if authenticated {
            req = req.extension(test_fixture_scoped());
        }
        req.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn test_list() {
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity(true, vec![user("u1", "did"), user("u2", "did")])),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: UserList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            res.users.into_iter().map(|u| u.id).collect::<Vec<_>>(),
            vec!["u1", "u2"]
        );
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity(true, vec![])),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_forbidden() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity(true, vec![])),
            false,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_group_not_found() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity(false, vec![])),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Security model I8: every member is re-checked against
    /// `identity/user/show` and unreadable ones are dropped.
    #[tokio::test]
    async fn test_list_drops_users_denied_by_show_policy() {
        let mut policy = MockPolicy::default();
        policy
            .expect_enforce()
            .returning(|policy_name, _, _, existing| {
                let hidden = policy_name == "identity/user/show"
                    && existing
                        .as_ref()
                        .and_then(|v| v.pointer("/user/id"))
                        .and_then(serde_json::Value::as_str)
                        == Some("hidden");
                if hidden {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                } else {
                    Ok(PolicyEvaluationResult::allowed_admin())
                }
            });
        let state = get_state_with_mock_policy(
            Provider::mocked_builder().mock_identity(identity(
                true,
                vec![user("visible", "did"), user("hidden", "other")],
            )),
            policy,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: UserList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            res.users.into_iter().map(|u| u.id).collect::<Vec<_>>(),
            vec!["visible"]
        );
    }

    /// A non-`Forbidden` policy failure is propagated, not treated as a drop.
    #[tokio::test]
    async fn test_list_propagates_policy_error() {
        let mut policy = MockPolicy::default();
        policy.expect_enforce().returning(|policy_name, _, _, _| {
            if policy_name == "identity/user/show" {
                Err(PolicyError::Dummy)
            } else {
                Ok(PolicyEvaluationResult::allowed_admin())
            }
        });
        let state = get_state_with_mock_policy(
            Provider::mocked_builder().mock_identity(identity(true, vec![user("u1", "did")])),
            policy,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Gate B2: the group is keyed under `existing`, the target is null; each
    /// member is checked with the user under `existing`.
    #[tokio::test]
    async fn test_list_policy_input_contract() {
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder().mock_identity(identity(true, vec![user("u1", "did")])),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let calls = policy.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].policy_name, "identity/group/user/list");
        assert_eq!(calls[1].policy_name, "identity/user/show");
        for (call, key) in calls.iter().zip(["group", "user"]) {
            assert_eq!(call.target, serde_json::Value::Null);
            policy_contract::assert_existing_presence(&call.existing, true);
            let existing = call.existing.as_ref().unwrap();
            policy_contract::assert_object_keys(existing, &[key]);
            policy_contract::assert_no_secrets(existing);
        }
    }
}
