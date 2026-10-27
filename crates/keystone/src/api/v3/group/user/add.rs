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
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Add a user to a group.
#[utoipa::path(
    put,
    path = "/{user_id}",
    operation_id = "/groups/group_id/users/user_id:add",
    params(
        ("group_id" = String, Path, description = "The group ID."),
        ("user_id" = String, Path, description = "The user ID.")
    ),
    responses(
        (status = NO_CONTENT, description = "Add a user to a group."),
        (status = 404, description = "Group, user or membership not found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    security(("x-auth" = [])),
    tag = "groups"
)]
#[tracing::instrument(name = "api::group_user_add", level = "debug", skip(state, user_auth))]
pub(super) async fn add(
    Auth(user_auth): Auth,
    Path((group_id, user_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let (existing, group_found, user_found) =
        super::load_membership(&state, &user_auth, &group_id, &user_id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/group/user/add",
            &user_auth,
            serde_json::Value::Null,
            Some(existing),
        )
        .await?;

    if !(group_found && user_found) {
        return Err(super::not_found(group_found, &group_id, &user_id));
    }

    state
        .provider
        .get_identity_provider()
        .add_user_to_group(
            &ExecutionContext::from_auth(&state, &user_auth),
            &user_id,
            &group_id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::identity::{Group, UserResponse, UserResponseBuilder};

    use super::super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

    fn group() -> Group {
        Group {
            id: "g".into(),
            name: "group".into(),
            domain_id: "did".into(),
            ..Default::default()
        }
    }

    fn user() -> UserResponse {
        UserResponseBuilder::default()
            .id("u")
            .domain_id("did")
            .enabled(true)
            .name("user")
            .build()
            .unwrap()
    }

    fn identity(group_found: bool, user_found: bool) -> MockIdentityProvider {
        let mut mock = MockIdentityProvider::default();
        mock.expect_get_group()
            .returning(move |_, _| Ok(group_found.then(group)));
        mock.expect_get_user()
            .returning(move |_, _| Ok(user_found.then(user)));
        mock
    }

    async fn call(mock: MockIdentityProvider, allowed: bool, authenticated: bool) -> StatusCode {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(mock),
            allowed,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut req = Request::builder().method("PUT").uri("/g/users/u");
        if authenticated {
            req = req.extension(test_fixture_scoped());
        }
        api.as_service()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn test_add() {
        let mut mock = identity(true, true);
        mock.expect_add_user_to_group().returning(|_, _, _| Ok(()));
        assert_eq!(call(mock, true, true).await, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_add_unauth() {
        assert_eq!(
            call(identity(true, true), true, false).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_add_forbidden() {
        assert_eq!(
            call(identity(true, true), false, true).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_add_group_not_found() {
        assert_eq!(
            call(identity(false, true), true, true).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn test_add_user_not_found() {
        assert_eq!(
            call(identity(true, false), true, true).await,
            StatusCode::NOT_FOUND
        );
    }

    /// The policy is enforced even when an object is missing (security model
    /// I10), with both objects under `existing`.
    #[tokio::test]
    async fn test_add_not_found_still_enforces_policy() {
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_identity(identity(false, true)))
                .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/g/users/u")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(policy.calls().len(), 1);
    }

    /// Gate B2: both objects are keyed under `existing`, the target is null.
    #[tokio::test]
    async fn test_add_policy_input_contract() {
        let mut mock = identity(true, true);
        mock.expect_add_user_to_group().returning(|_, _, _| Ok(()));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_identity(mock)).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/g/users/u")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/group/user/add");
        assert_eq!(calls[0].target, serde_json::Value::Null);
        policy_contract::assert_existing_presence(&calls[0].existing, true);
        let existing = calls[0].existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["group", "user"]);
        policy_contract::assert_no_secrets(existing);
    }
}
