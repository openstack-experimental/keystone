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

use super::types::{Credential, CredentialList, CredentialListParameters};
use crate::api::auth::Auth;
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
#[utoipa::path(
    get,
    path = "/",
    params(CredentialListParameters),
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
    Query(query): Query<CredentialListParameters>,
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

    let raw = state
        .provider
        .get_credential_provider()
        .list_credentials(
            &ExecutionContext::from_auth(&state, &user_auth),
            &query.into(),
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

    Ok((StatusCode::OK, Json(CredentialList { credentials })).into_response())
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
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::credential::types::CredentialList;
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

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
}
