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
//! `GET/POST /v4/oauth2/{domain_id}/device`, `POST .../device/login`,
//! `POST .../device/consent`: the RFC 8628 Device Authorization Grant's
//! browser verification page (ADR 0026 §7.C).
//!
//! Structurally parallel to `authorize.rs`'s login/consent steps, but there
//! is no `redirect_uri`/PKCE and the flow terminates in a static result
//! page rather than a redirect back to a relying party -- the polling
//! device, not this browser, receives the eventual token at `/token`.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use cadf::Outcome;
use cadf::OutcomeReason;
use secrecy::SecretString;
use serde::Deserialize;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::IdentityInfo;
use openstack_keystone_core_types::identity::{
    Domain as IdentityDomain, UserPasswordAuthRequestBuilder,
};
use openstack_keystone_core_types::oauth2_client::OAuth2ClientResource;
use openstack_keystone_core_types::oauth2_session::DeviceCodeGrant;

use super::html::{
    client_view, consent_page, device_entry_page, device_result_page, error_page, fetch_client,
    login_page, mfa_page, too_many_requests, view_of,
};
use super::renderer::{ClientView, ConsentCtx, DeviceEntryCtx, DeviceResultCtx, LoginCtx, MfaCtx};
use crate::api::common::PeerAddr;
use crate::audit::{
    CorrelationId, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_session_event,
};
use crate::keystone::ServiceState;

pub(super) const DEVICE_COOKIE_NAME: &str = "keystone_oauth2_device_code";

#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub(super) struct DeviceQuery {
    #[serde(default)]
    user_code: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct DeviceCodeForm {
    user_code: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct DeviceLoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct DeviceConsentForm {
    csrf_token: String,
    decision: String,
}

/// CSRF token derivation, mirroring `authorize.rs`'s but keyed on the
/// device grant's own identifiers instead of a `PreAuthSession`'s.
pub(super) fn compute_csrf_token(grant: &DeviceCodeGrant) -> Option<String> {
    super::html::compute_csrf_token(
        &grant.server_side_session_secret,
        &[&grant.device_code, &grant.user_code],
    )
}

pub(super) fn verify_csrf_token(grant: &DeviceCodeGrant, presented: &str) -> bool {
    compute_csrf_token(grant)
        .is_some_and(|expected| super::html::constant_time_eq(&expected, presented))
}

pub(super) async fn cookie_secure(state: &ServiceState, headers: &HeaderMap) -> bool {
    crate::api::common::oauth2_cookie_secure(state, headers).await
}

fn device_cookie(device_code: String, secure: bool) -> Cookie<'static> {
    Cookie::build((DEVICE_COOKIE_NAME, device_code))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .build()
}

fn render_entry(domain_id: &str, error: Option<&str>, prefill: &str) -> Response {
    device_entry_page(&DeviceEntryCtx {
        error: error.map(str::to_string),
        prefill: prefill.to_string(),
        action: format!("/v4/oauth2/{domain_id}/device"),
    })
}

fn render_login(
    domain_id: &str,
    client: &ClientView,
    grant: &DeviceCodeGrant,
    error: Option<&str>,
) -> Response {
    let Some(csrf_token) = compute_csrf_token(grant) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    login_page(&LoginCtx {
        client: client.clone(),
        csrf_token,
        error: error.map(str::to_string),
        action: format!("/v4/oauth2/{domain_id}/device/login"),
        // Federated sign-in is not offered on the device flow yet.
        idps: Vec::new(),
        federated_action: String::new(),
    })
}

pub(super) fn render_mfa(
    domain_id: &str,
    client: &ClientView,
    grant: &DeviceCodeGrant,
    error: Option<&str>,
) -> Response {
    let Some(csrf_token) = compute_csrf_token(grant) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    mfa_page(&MfaCtx {
        client: client.clone(),
        csrf_token,
        error: error.map(str::to_string),
        action: format!("/v4/oauth2/{domain_id}/device/mfa"),
    })
}

fn render_consent(domain_id: &str, client: &ClientView, grant: &DeviceCodeGrant) -> Response {
    let Some(csrf_token) = compute_csrf_token(grant) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    consent_page(&ConsentCtx {
        client: client.clone(),
        scopes: grant.scope.clone(),
        csrf_token,
        action: format!("/v4/oauth2/{domain_id}/device/consent"),
    })
}

fn render_result(granted: bool, client: &ClientView) -> Response {
    device_result_page(&DeviceResultCtx {
        granted,
        client: client.clone(),
    })
}

/// `GET /v4/oauth2/{domain_id}/device` (RFC 8628 §3.3). Renders the
/// user_code entry form, pre-filled from `verification_uri_complete`'s
/// `user_code` query parameter if present.
#[utoipa::path(
    get,
    path = "/{domain_id}/device",
    operation_id = "/oauth2:device",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        DeviceQuery,
    ),
    responses(
        (status = OK, description = "Code-entry form rendered", content_type = "text/html"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(name = "api::v4::oauth2::device_entry", level = "debug")]
pub(super) async fn device(
    Path(domain_id): Path<String>,
    Query(query): Query<DeviceQuery>,
) -> Result<Response, std::convert::Infallible> {
    Ok(render_entry(
        &domain_id,
        None,
        query.user_code.as_deref().unwrap_or_default(),
    ))
}

/// `POST /v4/oauth2/{domain_id}/device`: submit the `user_code`.
#[utoipa::path(
    post,
    path = "/{domain_id}/device",
    operation_id = "/oauth2:device_submit_code",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Login form rendered, or code-entry form re-rendered on failure", content_type = "text/html"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::device_submit_code",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn device_login_code(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    jar: CookieJar,
    Form(form): Form<DeviceCodeForm>,
) -> Result<Response, std::convert::Infallible> {
    // §7.B-equivalent pre-lookup throttle (mirrors `authorize.rs`'s
    // `/authorize` and `/authorize/login`): the `user_code` keyspace alone
    // is not a substitute for rate limiting a guess-and-submit endpoint.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Ok(too_many_requests(retry_after.as_secs()));
    }

    // The lookup itself is a single keyed storage read (not a linear scan
    // over every live code), so it does not carry the classic
    // string-comparison timing side channel a naive brute-force defense
    // would need to guard against separately.
    let grant = match state
        .provider
        .get_oauth2_session_provider()
        .get_device_code_grant_by_user_code(&state, form.user_code.trim())
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => {
            return Ok(render_entry(
                &domain_id,
                Some("invalid or expired code"),
                &form.user_code,
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 device code grant lookup failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    let client = client_view(&state, &grant.client_id).await;
    let jar = jar.add(device_cookie(
        grant.device_code.clone(),
        cookie_secure(&state, &headers).await,
    ));
    let response = render_login(&domain_id, &client, &grant, None);
    Ok((jar, response).into_response())
}

/// `POST /v4/oauth2/{domain_id}/device/login`.
#[utoipa::path(
    post,
    path = "/{domain_id}/device/login",
    operation_id = "/oauth2:device_login",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Consent form rendered, login re-rendered on failure, or the final result page for pre_authorized clients", content_type = "text/html"),
        (status = BAD_REQUEST, description = "Missing/expired grant or invalid CSRF token"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::device_login",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn device_login(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Form(form): Form<DeviceLoginForm>,
) -> Result<Response, std::convert::Infallible> {
    // §7.B "pre-hash enforcement" (mirrors `authorize_login`): global per-IP
    // limiter before any password hashing work. The per-user throttle inside
    // `authenticate_by_password` (ADR 0010) only engages after an account is
    // known to exist, so it alone does not stop a single IP from spraying
    // many different usernames here.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Ok(too_many_requests(retry_after.as_secs()));
    }

    let Some(device_code) = jar.get(DEVICE_COOKIE_NAME).map(|c| c.value().to_string()) else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "code expired; please restart",
        ));
    };
    let grant = match state
        .provider
        .get_oauth2_session_provider()
        .get_device_code_grant(&state, &device_code)
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => {
            return Ok(error_page(
                StatusCode::BAD_REQUEST,
                "code expired; please restart",
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 device code grant lookup failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    if !verify_csrf_token(&grant, &form.csrf_token) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired form submission; please restart",
        ));
    }

    let client_res = fetch_client(&state, &grant.client_id).await;
    let client = view_of(client_res.as_ref(), &grant.client_id);

    let auth_req = match UserPasswordAuthRequestBuilder::default()
        .name(form.username.clone())
        .domain(IdentityDomain {
            id: Some(domain_id.clone()),
            name: None,
        })
        .password(SecretString::from(form.password.clone()))
        .build()
    {
        Ok(req) => req,
        Err(_) => {
            return Ok(render_login(
                &domain_id,
                &client,
                &grant,
                Some("invalid username or password"),
            ));
        }
    };

    let exec = ExecutionContext::internal(&state);
    let auth_result = state
        .provider
        .get_identity_provider()
        .authenticate_by_password(&exec, &auth_req)
        .await;
    let auth_result = match auth_result {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "oauth2 device login failed");
            emit_oauth2_session_event(
                &state.audit_dispatcher,
                &correlation_id.0,
                "authenticate",
                build_initiator_unknown(),
                &grant.client_id,
                Outcome::Failure,
                Some(OutcomeReason::literal("InvalidCredentials")),
            );
            return Ok(render_login(
                &domain_id,
                &client,
                &grant,
                Some("invalid username or password"),
            ));
        }
    };

    let IdentityInfo::User(user_info) = &auth_result.principal.identity else {
        return Ok(error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        ));
    };
    let user_id = user_info.user_id.clone();
    let now = chrono::Utc::now().timestamp();

    let factors = match super::mfa::required_factors(&state, &user_id).await {
        Ok(f) => f,
        Err(e) => {
            // Fail closed: never skip a second factor because the lookup failed.
            tracing::warn!(error = %e, "oauth2 second-factor lookup failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };
    if !factors.is_empty() {
        return Ok(
            match state
                .provider
                .get_oauth2_session_provider()
                .begin_device_mfa(&state, &device_code, &user_id, factors)
                .await
            {
                Ok(pending) => render_mfa(&domain_id, &client, &pending, None),
                Err(e) => {
                    tracing::warn!(error = %e, "oauth2 device code grant update failed");
                    error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                }
            },
        );
    }

    let grant = match state
        .provider
        .get_oauth2_session_provider()
        .mark_device_authenticated(
            &state,
            &device_code,
            &user_id,
            now,
            super::mfa::amr_for(&[]),
        )
        .await
    {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 device code grant update failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        &correlation_id.0,
        "authenticate",
        build_initiator_from_user_id(&user_id, &grant.domain_id),
        &grant.client_id,
        Outcome::Success,
        None,
    );

    Ok(after_device_authentication(
        &state,
        &domain_id,
        client_res.as_ref(),
        &grant,
        &correlation_id.0,
    )
    .await)
}

/// Everything after a completed device login (password and any second
/// factor): skip consent for `pre_authorized` clients, otherwise render it.
pub(super) async fn after_device_authentication(
    state: &ServiceState,
    domain_id: &str,
    client: Option<&OAuth2ClientResource>,
    grant: &DeviceCodeGrant,
    correlation_id: &str,
) -> Response {
    // `pre_authorized` skips consent only, never login (same invariant as
    // `authorize.rs`): a `pre_authorized` client can never carry
    // `openstack:api` in `allowed_scopes` (enforced at CRUD time), so
    // skipping consent here cannot silently grant OpenStack authorization.
    if client.is_some_and(|c| c.pre_authorized) {
        return finish_decision(state, grant, true, correlation_id).await;
    }

    render_consent(domain_id, &view_of(client, &grant.client_id), grant)
}

/// `POST /v4/oauth2/{domain_id}/device/consent`.
#[utoipa::path(
    post,
    path = "/{domain_id}/device/consent",
    operation_id = "/oauth2:device_consent",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Final result page rendered", content_type = "text/html"),
        (status = BAD_REQUEST, description = "Missing/expired grant, not signed in, or invalid CSRF token"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::device_consent",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn device_consent(
    Path(_domain_id): Path<String>,
    State(state): State<ServiceState>,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Form(form): Form<DeviceConsentForm>,
) -> Result<Response, std::convert::Infallible> {
    let Some(device_code) = jar.get(DEVICE_COOKIE_NAME).map(|c| c.value().to_string()) else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "code expired; please restart",
        ));
    };
    let grant = match state
        .provider
        .get_oauth2_session_provider()
        .get_device_code_grant(&state, &device_code)
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => {
            return Ok(error_page(
                StatusCode::BAD_REQUEST,
                "code expired; please restart",
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 device code grant lookup failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    if !verify_csrf_token(&grant, &form.csrf_token) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired form submission; please restart",
        ));
    }
    if grant.user_id.is_none() {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "not signed in; please restart",
        ));
    }

    let granted = form.decision == "allow";
    Ok(finish_decision(&state, &grant, granted, &correlation_id.0).await)
}

/// Complete the flow after consent is known (explicit consent POST, or the
/// `pre_authorized` skip from `device_login`): stamp the terminal decision
/// and show the static result page. Unlike `authorize.rs`'s `finish_consent`,
/// there is no redirect target -- the polling device, not this browser,
/// receives the eventual token at `/token`.
pub(super) async fn finish_decision(
    state: &ServiceState,
    grant: &DeviceCodeGrant,
    granted: bool,
    correlation_id: &str,
) -> Response {
    let client = client_view(state, &grant.client_id).await;
    match state
        .provider
        .get_oauth2_session_provider()
        .mark_device_decision(state, &grant.device_code, granted)
        .await
    {
        Ok(_) => {
            emit_oauth2_session_event(
                &state.audit_dispatcher,
                correlation_id,
                "authorize",
                grant
                    .user_id
                    .as_deref()
                    .map_or_else(build_initiator_unknown, |user_id| {
                        build_initiator_from_user_id(user_id, &grant.domain_id)
                    }),
                &grant.client_id,
                if granted {
                    Outcome::Success
                } else {
                    Outcome::Failure
                },
                (!granted).then(|| OutcomeReason::literal("ConsentDenied")),
            );
            render_result(granted, &client)
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 device code grant decision update failed");
            error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use sea_orm::DatabaseConnection;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;

    use super::super::openapi_router;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn post_form(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn rate_limited_state(provider: crate::provider::ProviderBuilder) -> Arc<Service> {
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
        Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::default(),
                provider.build().unwrap(),
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_device_submit_code_rate_limited_by_ip_before_lookup() {
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_device_code_grant_by_user_code()
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder().mock_oauth2_session(session_mock);
        let state = rate_limited_state(provider).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let client_addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();

        let mut req1 = post_form("/domain-1/device", "user_code=AAAA-AAAA");
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        // First request consumes the single burst token and reaches the
        // (mocked) lookup, which reports "not found" -- rendered as 200 OK
        // with an inline error, not a distinct status.
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::OK
        );

        let mut req2 = post_form("/domain-1/device", "user_code=BBBB-BBBB");
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        // Burst exhausted: rejected by the IP limiter before the lookup runs
        // for a second guess, regardless of which code is guessed next.
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn test_device_login_rate_limited_by_ip_before_password_check() {
        let provider = Provider::mocked_builder();
        let state = rate_limited_state(provider).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let client_addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let form = "csrf_token=x&username=alice&password=guess";

        let mut req1 = post_form("/domain-1/device/login", form);
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        // First request consumes the single burst token and reaches the
        // no-device-cookie check (no password hashing was ever attempted).
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        let mut req2 = post_form("/domain-1/device/login", form);
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        // Burst exhausted: rejected by the IP limiter before any password
        // check, regardless of which username is guessed next.
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    // ---- second-factor (TOTP) step ----

    use http_body_util::BodyExt;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthenticationError, AuthenticationResultBuilder, AuthzInfoBuilder,
        IdentityInfo, PrincipalInfo, ScopeInfo, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::identity::IdentityProviderError;
    use openstack_keystone_core_types::oauth2_session::{DeviceCodeGrant, DeviceGrantStatus};

    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;

    fn grant(pending: bool, attempts: u32) -> DeviceCodeGrant {
        DeviceCodeGrant {
            device_code: "dc-1".into(),
            user_code: "BCDFGHJK".into(),
            domain_id: "domain-1".into(),
            client_id: "client-1".into(),
            scope: vec!["openid".into()],
            status: DeviceGrantStatus::Pending,
            user_id: None,
            auth_time: None,
            amr: vec![],
            nonce: None,
            server_side_session_secret: "secret".into(),
            last_polled_at: None,
            created_at: 0,
            expires_at: 1_000_000_000,
            pending_user_id: pending.then(|| "user-1".to_string()),
            pending_factors: if pending { vec!["totp".into()] } else { vec![] },
            mfa_attempts: attempts,
        }
    }

    fn device_post(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("POST")
            .header("cookie", "keystone_oauth2_device_code=dc-1")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn user_auth_result() -> openstack_keystone_core_types::auth::AuthenticationResult {
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("user-1")
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(
                AuthzInfoBuilder::default()
                    .scope(ScopeInfo::Unscoped)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    fn client_provider() -> MockOauth2ClientProvider {
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get_by_client_id().returning(|_, _| {
            Ok(Some(
                openstack_keystone_core_types::oauth2_client::OAuth2ClientResource {
                    client_id: "client-1".into(),
                    provider_id: "provider-1".into(),
                    domain_id: "domain-1".into(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    token_endpoint_auth_method: "none".into(),
                    grant_types: vec![],
                    require_pkce: true,
                    allowed_scopes: vec![],
                    pre_authorized: false,
                    enabled: true,
                    claims_template: Default::default(),
                    created_at: 0,
                    updated_at: 0,
                    deleted_at: None,
                    name: "CLI".into(),
                    description: None,
                    logo_uri: None,
                    policy_uri: None,
                    tos_uri: None,
                    contacts: vec![],
                },
            ))
        });
        mock
    }

    async fn body_text(response: axum::response::Response) -> String {
        String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_device_login_with_totp_credential_renders_mfa() {
        let csrf = super::compute_csrf_token(&grant(false, 0)).unwrap();
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_device_code_grant()
            .returning(|_, _| Ok(Some(grant(false, 0))));
        // `mark_device_authenticated` has no expectation: calling it would panic.
        session_mock
            .expect_begin_device_mfa()
            .returning(|_, _, _, _| Ok(grant(true, 0)));
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _| Ok(user_auth_result()));
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                openstack_keystone_core_types::identity::UserResponseBuilder::default()
                    .id("user-1")
                    .name("alice")
                    .domain_id("domain-1")
                    .enabled(true)
                    .build()
                    .unwrap(),
            ))
        });
        let mut credential_mock = crate::credential::MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .returning(|_, _, _| {
                Ok(vec![
                    openstack_keystone_core_types::credential::CredentialBuilder::default()
                        .id("cred-1")
                        .blob(r#"{"seed": "x"}"#)
                        .r#type("totp")
                        .user_id("user-1")
                        .build()
                        .unwrap(),
                ])
            });
        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_credential(credential_mock)
            .mock_oauth2_client(client_provider());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(device_post(
                "/domain-1/device/login",
                &format!("csrf_token={csrf}&username=alice&password=pw"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(body.contains("name=\"passcode\""));
        assert!(body.contains("CLI"));
    }

    #[tokio::test]
    async fn test_device_mfa_correct_code_records_mfa_amr_and_renders_consent() {
        let csrf = super::compute_csrf_token(&grant(true, 0)).unwrap();
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_device_code_grant()
            .returning(|_, _| Ok(Some(grant(true, 0))));
        session_mock
            .expect_record_device_mfa_attempt()
            .times(1)
            .returning(|_, _| Ok(grant(true, 1)));
        session_mock
            .expect_mark_device_authenticated()
            .withf(|_, _, user_id, _, amr| user_id == "user-1" && *amr == ["pwd", "otp", "mfa"])
            .returning(|_, _, _, _, _| {
                let mut g = grant(false, 0);
                g.user_id = Some("user-1".into());
                Ok(g)
            });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_totp()
            .returning(|_, _| Ok(user_auth_result()));
        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_oauth2_client(client_provider());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(device_post(
                "/domain-1/device/mfa",
                &format!("csrf_token={csrf}&factor=totp&passcode=123456"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("name=\"decision\""));
    }

    #[tokio::test]
    async fn test_device_mfa_wrong_code_exhausting_attempts_denies_the_grant() {
        let csrf = super::compute_csrf_token(&grant(true, 0)).unwrap();
        let max = openstack_keystone_config::Oauth2Provider::default().mfa_max_attempts;
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_device_code_grant()
            .returning(|_, _| Ok(Some(grant(true, 0))));
        session_mock
            .expect_record_device_mfa_attempt()
            .returning(move |_, _| Ok(grant(true, max)));
        session_mock
            .expect_mark_device_decision()
            .withf(|_, _, granted| !*granted)
            .times(1)
            .returning(move |_, _, _| Ok(grant(true, max)));
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_totp()
            .returning(|_, _| {
                Err(IdentityProviderError::Authentication {
                    source: AuthenticationError::TotpPasscodeInvalid,
                })
            });
        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(device_post(
                "/domain-1/device/mfa",
                &format!("csrf_token={csrf}&factor=totp&passcode=000000"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_device_mfa_without_pending_factor_is_bad_request() {
        let csrf = super::compute_csrf_token(&grant(false, 0)).unwrap();
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_device_code_grant()
            .returning(|_, _| Ok(Some(grant(false, 0))));
        let provider = Provider::mocked_builder().mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(device_post(
                "/domain-1/device/mfa",
                &format!("csrf_token={csrf}&factor=totp&passcode=123456"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
