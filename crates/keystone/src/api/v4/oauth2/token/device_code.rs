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
//! RFC 8628 `device_code` grant.

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use cadf::{Outcome, OutcomeReason};
use dashmap::DashMap;
use governor::clock::Clock as _;
use openstack_keystone_core::oauth2_client::{IdTokenParams, TemplateScope, build_id_token_claims};
use openstack_keystone_core::oauth2_session::{DevicePollOutcome, IssueRefreshTokenRequest};
use openstack_keystone_core_types::oauth2_client::{GrantType, OidcAccessTokenClaims};
use sha2::{Digest, Sha256};

use crate::audit::{
    Oauth2Grant, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_grant_event,
};
use crate::keystone::ServiceState;

use super::common::*;
use super::{Oauth2TokenError, TokenForm, TokenResponse};
use crate::api::v4::oauth2::well_known::base_url;

/// Upper bound on tracked quiet-period entries, so an attacker spraying
/// random `device_code` values cannot grow the map without limit. Once full
/// (after sweeping expired entries) new bad codes simply are not tracked;
/// the per-IP and per-client limiters still apply to them.
const QUIET_PERIOD_MAX_ENTRIES: usize = 100_000;

/// `sha256(client_id || 0x00 || device_code)` -> instant until which polls with
/// that code are refused. Node-local and in-memory on purpose: it only exists
/// to keep invalid polls away from Raft, and is not security-critical state.
static QUIET_PERIOD: LazyLock<DashMap<[u8; 32], Instant>> = LazyLock::new(DashMap::new);

/// The `client_id` is part of the key so a poll with a mismatched
/// `client_id` cannot throttle the legitimate owner of the code.
fn quiet_period_key(client_id: &str, device_code: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(client_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(device_code.as_bytes());
    hasher.finalize().into()
}

/// Remaining quiet time for `key`, if it is still in force.
fn quiet_period_remaining(key: &[u8; 32]) -> Option<Duration> {
    let until = *QUIET_PERIOD.get(key)?;
    let remaining = until.checked_duration_since(Instant::now());
    if remaining.is_none() {
        QUIET_PERIOD.remove_if(key, |_, u| *u <= Instant::now());
    }
    remaining
}

fn start_quiet_period(key: [u8; 32], period: Duration) {
    if QUIET_PERIOD.len() >= QUIET_PERIOD_MAX_ENTRIES {
        let now = Instant::now();
        QUIET_PERIOD.retain(|_, until| *until > now);
        if QUIET_PERIOD.len() >= QUIET_PERIOD_MAX_ENTRIES {
            return;
        }
    }
    QUIET_PERIOD.insert(key, Instant::now() + period);
}

/// RFC 8628 Device Authorization Grant polling arm (§3.4, §3.5, ADR 0026
/// §7.C). `client_id` is accepted but not authenticated against a
/// `client_secret` -- device flow clients are overwhelmingly public/native
/// applications, matching `/device_authorization`'s own posture. The
/// client is validated via `validate_device_code_client` *before* the
/// poll (which fetch-and-deletes an `Authorized` grant), and
/// `poll_device_code_grant` checks the grant's binding to both `client_id`
/// and the URL path's domain before consuming it (same bug class as the
/// cross-domain Token Exchange forgery this ADR's implementation
/// previously fixed: a grant must only ever be redeemable by the client
/// it was issued to, in the domain it was issued in). A rejected client is
/// audited as a `failure`.
pub(super) async fn handle_device_code_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    peer_addr: Option<std::net::SocketAddr>,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, _)) = client_credentials_from_request(headers, form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(device_code) = form.device_code.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: device_code",
        ));
    };

    // Every poll is an unauthenticated Raft read and a `Pending` one is a
    // write, so throttle on the source IP and the (unverified) client_id
    // before touching storage (ADR 0026 §7.C), as the refresh arm does.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(headers, peer_addr.map(|a| a.ip()))
    {
        return Err(Oauth2TokenError::too_many_requests(
            retry_after.as_secs().max(1),
        ));
    }
    if let Err(not_until) = state.oauth2_token_rate_limiter.check_key(&client_id) {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    // A code already answered with `invalid_grant`/`expired_token` stays
    // refused for the configured quiet period, without a storage lookup.
    let quiet_key = quiet_period_key(&client_id, &device_code);
    if let Some(remaining) = quiet_period_remaining(&quiet_key) {
        return Err(Oauth2TokenError::too_many_requests(
            remaining.as_secs().max(1),
        ));
    }
    let quiet_period = Duration::from_secs(u64::from(
        oauth2_cfg.device_code_invalid_quiet_period_seconds,
    ));

    // Validated *before* the poll, which fetch-and-deletes the grant once
    // it reports `Authorized`: a client disabled, deleted, foreign to
    // `domain_id`, or missing the `device_code` grant type must not burn a
    // grant it is not entitled to redeem, and the user can retry once the
    // client is fixed.
    let client = match validate_device_code_client(state, domain_id, &client_id).await {
        Ok(client) => client,
        Err(e) => {
            emit_oauth2_grant_event(
                &state.audit_dispatcher,
                correlation_id,
                "authenticate",
                build_initiator_unknown(),
                Oauth2Grant {
                    client_id: &client_id,
                    grant_type: "device_code",
                },
                Outcome::Failure,
                Some(OutcomeReason::variant(e.error_code())),
            );
            return Err(e);
        }
    };

    // Before the poll: it fetch-and-deletes an authorized grant, which a nonce
    // challenge or a malformed, stale or missing proof must not consume. Every
    // poll carries its own proof (ADR 0043 §3).
    let confirmation = super::dpop::bind_token_request(
        state,
        domain_id,
        headers,
        peer_addr,
        &client,
        openstack_keystone_config::DpopMode::Disabled,
        super::dpop::SourceLimit::Charged,
    )
    .await?;

    let outcome = state
        .provider
        .get_oauth2_session_provider()
        .poll_device_code_grant(state, &device_code, domain_id, &client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 device code grant poll failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let record = match outcome {
        DevicePollOutcome::InvalidGrant => {
            start_quiet_period(quiet_key, quiet_period);
            return Err(Oauth2TokenError::invalid_grant(
                "device_code is invalid or does not belong to this client_id",
            ));
        }
        DevicePollOutcome::Expired => {
            start_quiet_period(quiet_key, quiet_period);
            return Err(Oauth2TokenError::expired_token());
        }
        DevicePollOutcome::SlowDown => return Err(Oauth2TokenError::slow_down()),
        DevicePollOutcome::Pending => return Err(Oauth2TokenError::authorization_pending()),
        DevicePollOutcome::Denied => return Err(Oauth2TokenError::access_denied()),
        DevicePollOutcome::Authorized(record) => record,
    };

    let (Some(user_id), Some(auth_time)) = (record.user_id.clone(), record.auth_time) else {
        tracing::warn!("oauth2 device code grant authorized without user_id/auth_time");
        return Err(Oauth2TokenError::internal("token issuance failed"));
    };

    // A grant bound when the flow started needs a proof from that key; an
    // unbound one takes the key of the proof, if any. The poll has already
    // spent an authorized grant, so a valid proof from another key ends it,
    // the same as for an authorization code.
    let confirmation =
        super::dpop::reconcile_code_binding(record.dpop_jkt.as_deref(), confirmation)?;
    let jkt = confirmation.as_ref().map(|c| c.jkt.clone());

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let id_lifetime = i64::from(oauth2_cfg.id_token_lifetime_minutes) * 60;

    // Issued before the access token so the token can carry the session id
    // (`sid`) of its refresh family for RFC 7009 revocation.
    let (sid, refresh_token) = if client.grant_types.contains(&GrantType::RefreshToken) {
        let (record_rt, bearer) = state
            .provider
            .get_oauth2_session_provider()
            .issue_refresh_token(
                state,
                IssueRefreshTokenRequest {
                    domain_id: domain_id.to_string(),
                    client_id: client.client_id.clone(),
                    user_id: user_id.clone(),
                    scope: record.scope.clone(),
                    amr: record.amr.clone(),
                    upstream: record.upstream.clone(),
                    dpop_jkt: jkt,
                },
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 refresh token issuance failed");
                Oauth2TokenError::internal("token issuance failed")
            })?;
        (Some(record_rt.family_id), Some(bearer))
    } else {
        (None, None)
    };

    let signed = async {
        let access_claims = OidcAccessTokenClaims {
            iss: issuer.clone(),
            sub: user_id.clone(),
            aud: client_id.clone(),
            exp: now + access_lifetime,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            scope: record.scope.join(" "),
            token_use: "access".to_string(),
            family_id: sid.clone(),
            cnf: confirmation.clone(),
        };
        let access_token = sign_jwt(state, domain_id, &access_claims).await?;

        let id_token = if record.scope.iter().any(|s| s == "openid") {
            let id_claims = build_id_token_claims(
                state,
                &client,
                IdTokenParams {
                    issuer,
                    user_id: user_id.clone(),
                    client_id: client_id.clone(),
                    now,
                    lifetime: id_lifetime,
                    auth_time,
                    nonce: record.nonce.clone(),
                    amr: record.amr.clone(),
                    at_hash: Some(compute_at_hash(&access_token)),
                    // Device grants have no SSO session, hence no `sid`.
                    sid: None,
                },
                &record.scope,
                &TemplateScope::default(),
            )
            .await
            .map_err(id_token_error)?;
            Some(sign_jwt(state, domain_id, &id_claims).await?)
        } else {
            None
        };
        Ok::<_, Oauth2TokenError>((access_token, id_token))
    }
    .await;
    let (access_token, id_token) = match signed {
        Ok(tokens) => tokens,
        Err(e) => {
            discard_refresh_family(state, sid.as_deref()).await;
            return Err(e);
        }
    };

    emit_oauth2_grant_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_from_user_id(&user_id, domain_id),
        Oauth2Grant {
            client_id: &client_id,
            grant_type: "device_code",
        },
        Outcome::Success,
        None,
    );

    let response = TokenResponse {
        issued_token_type: None,
        access_token,
        token_type: super::dpop::token_type(confirmation.as_ref()),
        expires_in: access_lifetime,
        scope: record.scope.join(" "),
        id_token,
        refresh_token,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{extract::ConnectInfo, http::StatusCode};
    use sea_orm::DatabaseConnection;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::oauth2_session::DevicePollOutcome;
    use openstack_keystone_core::policy::MockPolicy;

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{
        dpop_proof, dpop_test_jkt, json_body, jwt_claims, ok_key_mock, public_authz_code_client,
        request,
    };
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn device_form(device_code: &str) -> String {
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &client_id=client-1&device_code={device_code}"
        )
    }

    /// A registered, enabled `domain-1` client holding the `device_code`
    /// grant type: passes the pre-poll client validation, so tests can
    /// focus on the poll itself.
    async fn valid_device_client()
    -> openstack_keystone_core_types::oauth2_client::OAuth2ClientResource {
        let mut client = public_authz_code_client().await;
        client.grant_types =
            vec![openstack_keystone_core_types::oauth2_client::GrantType::DeviceCode];
        client
    }

    #[tokio::test]
    async fn test_device_code_rate_limit_returns_429_before_lookup() {
        let config = Config {
            oauth2: openstack_keystone_config::Oauth2Provider {
                token_rate_limit_burst_size: 1,
                token_rate_limit_replenish_per_minute: 1,
                allow_host_header_issuer: true,
                ..Default::default()
            },
            ..Config::default()
        };

        let client = valid_device_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut session_mock = MockOauth2SessionProvider::default();
        // Exactly one poll may reach storage: the second is rejected by the
        // per-client limiter first.
        session_mock
            .expect_poll_device_code_grant()
            .times(1)
            .returning(|_, _, _, _| Ok(DevicePollOutcome::Pending));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .build()
            .unwrap();
        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::default(),
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let client_addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut req1 = request(&device_form("rate-limit-code"));
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        let resp1 = api.as_service().oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp1).await["error"], "authorization_pending");

        let mut req2 = request(&device_form("rate-limit-code"));
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        let resp2 = api.as_service().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp2.headers().contains_key("retry-after"));
    }

    #[tokio::test]
    async fn test_device_code_ip_rate_limit_returns_429_before_lookup() {
        let config = Config {
            rate_limit_global_ip: openstack_keystone_config::RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            oauth2: openstack_keystone_config::Oauth2Provider {
                allow_host_header_issuer: true,
                ..Default::default()
            },
            ..Config::default()
        };

        let client = valid_device_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_poll_device_code_grant()
            .times(1)
            .returning(|_, _, _, _| Ok(DevicePollOutcome::Pending));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .build()
            .unwrap();
        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::default(),
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let client_addr: SocketAddr = "203.0.113.10:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut req1 = request(&device_form("ip-limit-code"));
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        let mut req2 = request(&device_form("ip-limit-code-2"));
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_quiet_period_key_is_bound_to_client_id() {
        assert_ne!(
            super::quiet_period_key("client-a", "code"),
            super::quiet_period_key("client-b", "code")
        );
        // The separator keeps `("ab", "c")` and `("a", "bc")` apart.
        assert_ne!(
            super::quiet_period_key("ab", "c"),
            super::quiet_period_key("a", "bc")
        );
    }

    #[tokio::test]
    async fn test_device_code_quiet_period_after_unknown_code() {
        let client = valid_device_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut session_mock = MockOauth2SessionProvider::default();
        // The second poll with the same code must be refused without a
        // storage lookup.
        session_mock
            .expect_poll_device_code_grant()
            .times(1)
            .returning(|_, _, _, _| Ok(DevicePollOutcome::InvalidGrant));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let resp1 = api
            .as_service()
            .oneshot(request(&device_form("quiet-unknown-code")))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp1).await["error"], "invalid_grant");

        let resp2 = api
            .as_service()
            .oneshot(request(&device_form("quiet-unknown-code")))
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = resp2
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap();
        assert!((1..=300).contains(&retry_after));

        // A different code is unaffected.
        let client = valid_device_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut other = MockOauth2SessionProvider::default();
        other
            .expect_poll_device_code_grant()
            .times(1)
            .returning(|_, _, _, _| Ok(DevicePollOutcome::Expired));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(other);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let resp3 = api
            .as_service()
            .oneshot(request(&device_form("quiet-other-code")))
            .await
            .unwrap();
        assert_eq!(json_body(resp3).await["error"], "expired_token");
        let resp4 = api
            .as_service()
            .oneshot(request(&device_form("quiet-other-code")))
            .await
            .unwrap();
        assert_eq!(resp4.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_device_code_slow_down_does_not_start_quiet_period() {
        let client = valid_device_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_poll_device_code_grant()
            .times(2)
            .returning(|_, _, _, _| Ok(DevicePollOutcome::SlowDown));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        for _ in 0..2 {
            let resp = api
                .as_service()
                .oneshot(request(&device_form("slow-down-code")))
                .await
                .unwrap();
            assert_eq!(json_body(resp).await["error"], "slow_down");
        }
    }

    /// Redeem for `client` and assert the pre-poll client validation
    /// rejects it with `status`/`error` -- and that the grant was not
    /// consumed (the poll never runs, so the user can retry once the
    /// client is fixed).
    async fn reject_before_poll(
        client: Option<openstack_keystone_core_types::oauth2_client::OAuth2ClientResource>,
        code: &str,
        status: StatusCode,
        error: &str,
    ) {
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Disabled));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(client.clone()));
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock.expect_poll_device_code_grant().times(0);
        session_mock.expect_issue_refresh_token().never();
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let resp = api
            .as_service()
            .oneshot(request(&device_form(code)))
            .await
            .unwrap();
        assert_eq!(resp.status(), status);
        assert_eq!(json_body(resp).await["error"], error);
    }

    #[tokio::test]
    async fn test_device_code_disabled_client_is_invalid_client() {
        let mut client = valid_device_client().await;
        client.enabled = false;
        reject_before_poll(
            Some(client),
            "disabled-client-code",
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        )
        .await;
    }

    #[tokio::test]
    async fn test_device_code_deleted_client_is_invalid_client() {
        let mut client = valid_device_client().await;
        client.deleted_at = Some(1);
        reject_before_poll(
            Some(client),
            "deleted-client-code",
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        )
        .await;
    }

    #[tokio::test]
    async fn test_device_code_client_without_device_grant_type_is_unauthorized_client() {
        // `public_authz_code_client` holds only `authorization_code`.
        let client = public_authz_code_client().await;
        reject_before_poll(
            Some(client),
            "no-device-grant-code",
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
        )
        .await;
    }

    #[tokio::test]
    async fn test_device_code_unknown_client_is_invalid_client() {
        reject_before_poll(
            None,
            "unknown-client-code",
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        )
        .await;
    }
    const TOKEN_URL: &str = "http://localhost/v4/oauth2/domain-1/token";

    fn authorized_grant(
        dpop_jkt: Option<String>,
    ) -> openstack_keystone_core_types::oauth2_session::DeviceCodeGrant {
        use openstack_keystone_core_types::oauth2_session::{DeviceCodeGrant, DeviceGrantStatus};
        DeviceCodeGrant {
            device_code: "dc-1".into(),
            user_code: "BCDFGHJK".into(),
            domain_id: "domain-1".into(),
            client_id: "client-1".into(),
            scope: vec![],
            status: DeviceGrantStatus::Authorized,
            user_id: Some("user-1".into()),
            auth_time: Some(1000),
            amr: vec!["pwd".into()],
            nonce: None,
            server_side_session_secret: "secret".into(),
            last_polled_at: None,
            created_at: 0,
            expires_at: 1_000_000_000,
            pending_user_id: None,
            pending_factors: vec![],
            mfa_attempts: 0,
            pending_upstream: None,
            upstream: None,
            dpop_jkt,
        }
    }

    /// A state with DPoP `optional` whose poll reports `outcome` at most
    /// `polls` times.
    async fn dpop_state(outcome: DevicePollOutcome, polls: usize) -> crate::keystone::ServiceState {
        let client = valid_device_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_effective_dpop_mode()
            .returning(|_, _, _| Ok(openstack_keystone_config::DpopMode::Optional));
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_poll_device_code_grant()
            .times(polls)
            .returning(move |_, _, _, _| Ok(outcome.clone()));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_oauth2_key(ok_key_mock());
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        config.oauth2.dpop = openstack_keystone_config::DpopMode::Optional;
        config.mapping.cluster_salt = Some("dpop-test-salt".to_string().into());
        openstack_keystone_core::api::tests::get_mocked_state_with_config(
            provider, true, None, config,
        )
        .await
    }

    fn with_proof(code: &str, proof: Option<String>) -> axum::http::Request<axum::body::Body> {
        let mut req = request(&device_form(code));
        if let Some(proof) = proof {
            req.headers_mut().insert("DPoP", proof.parse().unwrap());
        }
        req
    }

    async fn fetch_nonce(api: &mut utoipa_axum::router::OpenApiRouter, code: &str) -> String {
        let response = api
            .as_service()
            .oneshot(with_proof(
                code,
                Some(dpop_proof(TOKEN_URL, "nonce-probe", None)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let nonce = response.headers()["dpop-nonce"]
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(json_body(response).await["error"], "use_dpop_nonce");
        nonce
    }

    #[tokio::test]
    async fn test_nonce_challenge_does_not_poll_the_grant() {
        let state = dpop_state(DevicePollOutcome::Pending, 0).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        assert!(
            !fetch_nonce(&mut api, "dpop-challenge-code")
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_bound_grant_with_matching_proof_issues_bound_token() {
        let state = dpop_state(
            DevicePollOutcome::Authorized(Box::new(authorized_grant(Some(dpop_test_jkt())))),
            1,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api, "dpop-bound-code").await;

        let response = api
            .as_service()
            .oneshot(with_proof(
                "dpop-bound-code",
                Some(dpop_proof(TOKEN_URL, "jti-1", Some(&nonce))),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "DPoP");
        assert_eq!(
            jwt_claims(body["access_token"].as_str().unwrap())["cnf"]["jkt"],
            dpop_test_jkt()
        );
    }

    #[tokio::test]
    async fn test_unbound_grant_takes_the_proof_key() {
        let state = dpop_state(
            DevicePollOutcome::Authorized(Box::new(authorized_grant(None))),
            1,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api, "dpop-unbound-code").await;

        let response = api
            .as_service()
            .oneshot(with_proof(
                "dpop-unbound-code",
                Some(dpop_proof(TOKEN_URL, "jti-2", Some(&nonce))),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "DPoP");
    }

    #[tokio::test]
    async fn test_bound_grant_without_proof_is_rejected() {
        let state = dpop_state(
            DevicePollOutcome::Authorized(Box::new(authorized_grant(Some(dpop_test_jkt())))),
            1,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(with_proof("dpop-noproof-code", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn test_bound_grant_with_another_key_is_rejected() {
        let state = dpop_state(
            DevicePollOutcome::Authorized(Box::new(authorized_grant(Some("A".repeat(43))))),
            1,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api, "dpop-other-code").await;

        let response = api
            .as_service()
            .oneshot(with_proof(
                "dpop-other-code",
                Some(dpop_proof(TOKEN_URL, "jti-3", Some(&nonce))),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn test_pending_poll_with_proof_stays_pending() {
        let state = dpop_state(DevicePollOutcome::Pending, 1).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let nonce = fetch_nonce(&mut api, "dpop-pending-code").await;

        let response = api
            .as_service()
            .oneshot(with_proof(
                "dpop-pending-code",
                Some(dpop_proof(TOKEN_URL, "jti-4", Some(&nonce))),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "authorization_pending");
    }
}
