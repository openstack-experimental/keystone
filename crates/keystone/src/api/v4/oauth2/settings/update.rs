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
//! OAuth2 domain settings: update. Raising the DPoP mode is allowed to the
//! domain manager; lowering it, or setting it below the global mode,
//! requires `admin` (ADR 0043 §1), enforced by Rego
//! (`policy/oauth2/settings/update.rego`).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::oauth2_settings::{
    DpopMode, Oauth2DomainSettings, Oauth2DomainSettingsResponse, Oauth2DomainSettingsUpdateRequest,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::audit::{CorrelationId, build_initiator_from_vsc, emit_oauth2_domain_settings_event};
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update the OAuth2 settings of a domain.
#[utoipa::path(
    put,
    path = "/{domain_id}/settings",
    operation_id = "/oauth2/settings:update",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    request_body = Oauth2DomainSettingsUpdateRequest,
    responses(
        (status = OK, description = "OAuth2 settings of the domain", body = Oauth2DomainSettingsResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_settings"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::settings::update",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    CorrelationId(correlation_id): CorrelationId,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<Oauth2DomainSettingsUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let provider = state.provider.get_oauth2_client_provider();
    let current =
        Oauth2DomainSettings::from(provider.get_domain_settings(&exec, &domain_id).await?);

    // The policy decides on the resulting state: the mode the domain ends up
    // with next to the global floor.
    let resulting = req.settings.dpop.unwrap_or(current.dpop);
    let global = state.config_manager.config.read().await.oauth2.dpop;
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/settings/update",
            &user_auth,
            serde_json::json!({"oauth2_settings": {
                "dpop": resulting,
                "global_dpop": openstack_keystone_api_types::v4::oauth2_settings::DpopMode::from(global),
            }}),
            Some(serde_json::json!({"oauth2_settings": current})),
        )
        .await?;

    // Only a change that switches DPoP on needs the server to be able to
    // issue nonces: re-sending the current state must not fail on a node
    // that lacks the salt.
    if resulting != DpopMode::Disabled && resulting != current.dpop {
        crate::api::v4::oauth2::ensure_dpop_configured(&state)?;
    }

    // The policy decided on `current`: the write is conditional on it, so a
    // change made in between cannot be overwritten under a decision taken
    // against a mode that is no longer stored (a domain manager could
    // otherwise lower a mode that was raised meanwhile).
    let mut update: openstack_keystone_core_types::oauth2_client::OAuth2DomainSettingsUpdate =
        req.settings.into();
    update.expected_dpop = Some(current.dpop.into());
    let updated = Oauth2DomainSettings::from(
        provider
            .update_domain_settings(&exec, &domain_id, update)
            .await?,
    );

    if updated.dpop != current.dpop {
        emit_oauth2_domain_settings_event(
            &state.audit_dispatcher,
            &correlation_id,
            build_initiator_from_vsc(&user_auth),
            &domain_id,
            current.dpop.into(),
            updated.dpop.into(),
        );
    }

    Ok((
        StatusCode::OK,
        Json(Oauth2DomainSettingsResponse { settings: updated }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
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
        get_capturing_state_with_config, get_mocked_state, get_mocked_state_with_config,
        policy_contract, test_fixture_scoped,
    };
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::{Provider, ProviderBuilder};
    use openstack_keystone_config::Config;

    fn request(body: &str, authenticated: bool) -> Request<Body> {
        let builder = Request::builder()
            .method("PUT")
            .uri("/domain-1/settings")
            .header(header::CONTENT_TYPE, "application/json");
        if authenticated {
            builder.extension(test_fixture_scoped())
        } else {
            builder
        }
        .body(Body::from(body.to_string()))
        .unwrap()
    }

    fn settings(dpop: core::DpopMode, updated_at: i64) -> core::OAuth2DomainSettings {
        core::OAuth2DomainSettings {
            domain_id: "domain-1".into(),
            dpop,
            updated_at,
        }
    }

    /// A config with the cluster salt DPoP needs.
    fn salted_config() -> Config {
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        config.mapping.cluster_salt = Some("dpop-test-salt".to_string().into());
        config
    }

    /// A provider whose domain is at `before` and ends up at `after`;
    /// `updates` is how many writes are expected.
    fn provider(before: core::DpopMode, after: core::DpopMode, updates: usize) -> ProviderBuilder {
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get_domain_settings()
            .returning(move |_, _| Ok(settings(before, 1)));
        mock.expect_update_domain_settings()
            .times(updates)
            // The write is conditional on the mode the policy decided on.
            .withf(move |_, domain_id, data| {
                domain_id == "domain-1" && data.expected_dpop == Some(before)
            })
            .returning(move |_, _, _| Ok(settings(after, 2)));
        Provider::mocked_builder().mock_oauth2_client(mock)
    }

    #[tokio::test]
    async fn test_update_sets_the_mode() {
        let state = get_mocked_state_with_config(
            provider(core::DpopMode::Disabled, core::DpopMode::Required, 1),
            true,
            None,
            salted_config(),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {"dpop": "required"}}"#, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2DomainSettingsResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.settings.dpop, DpopMode::Required);
        assert_eq!(res.settings.updated_at, 2);
    }

    #[tokio::test]
    async fn test_update_policy_input_contract() {
        let (state, policy) = get_capturing_state_with_config(
            provider(core::DpopMode::Optional, core::DpopMode::Required, 1),
            salted_config(),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {"dpop": "required"}}"#, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/oauth2/settings/update");
        policy_contract::assert_object_keys(&calls[0].target, &["oauth2_settings"]);
        // The resulting mode next to the global floor (default: disabled).
        assert_eq!(
            calls[0].target["oauth2_settings"],
            serde_json::json!({"dpop": "required", "global_dpop": "disabled"})
        );
        policy_contract::assert_existing_presence(&calls[0].existing, true);
        let existing = calls[0].existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["oauth2_settings"]);
        assert_eq!(existing["oauth2_settings"]["domain_id"], "domain-1");
        assert_eq!(existing["oauth2_settings"]["dpop"], "optional");
        policy_contract::assert_no_secrets(&calls[0].target);
        policy_contract::assert_no_secrets(existing);
    }

    #[tokio::test]
    async fn test_update_without_a_mode_keeps_the_stored_one_for_the_policy() {
        let (state, policy) = get_capturing_state_with_config(
            provider(core::DpopMode::Optional, core::DpopMode::Optional, 1),
            salted_config(),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {}}"#, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            policy.calls()[0].target["oauth2_settings"]["dpop"],
            "optional"
        );
    }

    /// Without `[mapping] cluster_salt` no nonce can be issued, so turning
    /// DPoP on would lock the domain out of `/token`: refused, nothing
    /// written. Turning it off needs no salt.
    #[tokio::test]
    async fn test_update_to_dpop_without_cluster_salt_is_refused() {
        for mode in ["optional", "required"] {
            let state = get_mocked_state(
                provider(core::DpopMode::Disabled, core::DpopMode::Disabled, 0),
                true,
                None,
            )
            .await;
            let mut api = openapi_router()
                .layer(TraceLayer::new_for_http())
                .with_state(state);
            let response = api
                .as_service()
                .oneshot(request(
                    &format!(r#"{{"settings": {{"dpop": "{mode}"}}}}"#),
                    true,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{mode}");
        }
    }

    #[tokio::test]
    async fn test_update_to_disabled_needs_no_cluster_salt() {
        let state = get_mocked_state(
            provider(core::DpopMode::Required, core::DpopMode::Disabled, 1),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {"dpop": "disabled"}}"#, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Re-sending the state a domain is in changes nothing, so it needs no
    /// salt either.
    #[tokio::test]
    async fn test_update_to_the_current_mode_needs_no_cluster_salt() {
        let state = get_mocked_state(
            provider(core::DpopMode::Required, core::DpopMode::Required, 1),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {"dpop": "required"}}"#, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The mode changed between the read the policy decided on and the
    /// write: the backend refuses and the caller learns it.
    #[tokio::test]
    async fn test_update_against_a_changed_mode_is_a_conflict() {
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get_domain_settings()
            .returning(|_, _| Ok(settings(core::DpopMode::Optional, 1)));
        mock.expect_update_domain_settings().returning(|_, _, _| {
            Err(
                openstack_keystone_core_types::oauth2_client::Oauth2ClientProviderError::Conflict(
                    "changed concurrently".into(),
                ),
            )
        });
        let state = get_mocked_state_with_config(
            Provider::mocked_builder().mock_oauth2_client(mock),
            true,
            None,
            salted_config(),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {"dpop": "optional"}}"#, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_update_policy_denied_writes_nothing() {
        let state = get_mocked_state(
            provider(core::DpopMode::Required, core::DpopMode::Disabled, 0),
            false,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {"dpop": "disabled"}}"#, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_unknown_mode_is_rejected() {
        let state = get_mocked_state(
            provider(core::DpopMode::Disabled, core::DpopMode::Disabled, 0),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {"dpop": "sometimes"}}"#, true))
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn test_update_unauthorized_without_auth() {
        let state = get_mocked_state(
            provider(core::DpopMode::Disabled, core::DpopMode::Disabled, 0),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(request(r#"{"settings": {"dpop": "required"}}"#, false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
