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
//! # List OS-EC2 credentials for a user

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::Ec2CredentialList;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List a user's EC2 credentials.
#[utoipa::path(
    get,
    path = "/{user_id}/credentials/OS-EC2",
    description = "List a user's EC2 credentials (OS-EC2 legacy API)",
    responses(
        (status = OK, description = "List of EC2 credentials", body = Ec2CredentialList),
    ),
    tag="OS-EC2"
)]
#[tracing::instrument(name = "api::os_ec2_list", level = "debug", skip(state))]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/os_ec2/read_credential",
            &user_auth,
            json!({"user_id": &user_id}),
            None,
        )
        .await?;

    let raw = state
        .provider
        .get_credential_provider()
        .list_credentials_for_user(
            &ExecutionContext::from_auth(&state, &user_auth),
            &user_id,
            Some("ec2"),
        )
        .await?;

    let credentials = raw
        .into_iter()
        .map(super::to_ec2_credential)
        .collect::<Result<Vec<_>, _>>()?;

    Ok((StatusCode::OK, Json(Ec2CredentialList { credentials })).into_response())
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

    use openstack_keystone_core_types::credential::CredentialBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::user::os_ec2::types::Ec2CredentialList;
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_list() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .withf(|_, uid: &'_ str, t: &Option<&str>| uid == "foo" && *t == Some("ec2"))
            .returning(|_, _, _| {
                Ok(vec![
                    CredentialBuilder::default()
                        .id("cred_id")
                        .blob(r#"{"access":"AKIA123","secret":"s3cr3t"}"#)
                        .r#type("ec2")
                        .user_id("foo")
                        .project_id("pid")
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
                    .uri("/foo/credentials/OS-EC2")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Ec2CredentialList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.credentials.len(), 1);
        assert_eq!(res.credentials[0].access, "AKIA123");
        assert_eq!(res.credentials[0].secret, "s3cr3t");
        assert_eq!(res.credentials[0].project_id, "pid");
    }

    #[tokio::test]
    async fn test_list_denied() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/credentials/OS-EC2")
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
            .oneshot(
                Request::builder()
                    .uri("/foo/credentials/OS-EC2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
