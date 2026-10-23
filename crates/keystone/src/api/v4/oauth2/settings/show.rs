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
//! OAuth2 domain settings: show.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::oauth2_settings::{
    Oauth2DomainSettings, Oauth2DomainSettingsResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Show the OAuth2 settings of a domain. A domain that was never configured
/// reports the defaults (`dpop: disabled`, `updated_at: 0`).
#[utoipa::path(
    get,
    path = "/{domain_id}/settings",
    operation_id = "/oauth2/settings:show",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "OAuth2 settings of the domain", body = Oauth2DomainSettingsResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_settings"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::settings::show",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = Oauth2DomainSettings::from(
        state
            .provider
            .get_oauth2_client_provider()
            .get_domain_settings(&ExecutionContext::from_auth(&state, &user_auth), &domain_id)
            .await?,
    );

    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/settings/show",
            &user_auth,
            serde_json::Value::Null,
            Some(serde_json::json!({"oauth2_settings": current})),
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(Oauth2DomainSettingsResponse { settings: current }),
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

    use openstack_keystone_api_types::v4::oauth2_settings::{
        DpopMode, Oauth2DomainSettingsResponse,
    };
    use openstack_keystone_core_types::oauth2_client as core;

    use super::super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;

    fn request(authenticated: bool) -> Request<Body> {
        let builder = Request::builder().uri("/domain-1/settings");
        if authenticated {
            builder.extension(test_fixture_scoped())
        } else {
            builder
        }
        .body(Body::empty())
        .unwrap()
    }

    fn provider() -> crate::provider::ProviderBuilder {
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get_domain_settings()
            .withf(|_, domain_id| domain_id == "domain-1")
            .returning(|_, _| {
                Ok(core::OAuth2DomainSettings {
                    domain_id: "domain-1".into(),
                    dpop: core::DpopMode::Optional,
                    updated_at: 42,
                })
            });
        Provider::mocked_builder().mock_oauth2_client(mock)
    }

    #[tokio::test]
    async fn test_show_returns_the_settings() {
        let state = get_mocked_state(provider(), true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2DomainSettingsResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.settings.domain_id, "domain-1");
        assert_eq!(res.settings.dpop, DpopMode::Optional);
        assert_eq!(res.settings.updated_at, 42);
    }

    #[tokio::test]
    async fn test_show_policy_input_contract() {
        let (state, policy) = get_capturing_state(provider()).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/oauth2/settings/show");
        assert!(calls[0].target.is_null());
        policy_contract::assert_existing_presence(&calls[0].existing, true);
        let existing = calls[0].existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["oauth2_settings"]);
        assert_eq!(existing["oauth2_settings"]["domain_id"], "domain-1");
        assert_eq!(existing["oauth2_settings"]["dpop"], "optional");
        policy_contract::assert_no_secrets(existing);
    }

    #[tokio::test]
    async fn test_show_policy_denied() {
        let state = get_mocked_state(provider(), false, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_show_unauthorized_without_auth() {
        let state = get_mocked_state(provider(), true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
