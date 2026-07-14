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
//! `GET /v4/oauth2/{domain_id}/authorize`, `POST .../authorize/login`,
//! `POST .../authorize/consent`: the human `authorization_code` flow with
//! mandatory PKCE (ADR 0026 §10 Phase 4, §1, §8).
//!
//! Unauthenticated at the `Auth`-extractor level like `/token`: this is
//! Keystone's first HTML surface. Only the `openid`/`profile`/`email`
//! display scopes are supported end to end in this phase --
//! `openstack:api` is rejected at request time (both here and defensively
//! again in `token.rs`) since resolving a project/domain OpenStack
//! authorization scope for a human token is not yet wired through the
//! consent step.

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use secrecy::SecretString;
use serde::Deserialize;
use sha2::Sha256;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_session::{
    IssueAuthorizationCodeRequest, StartPreAuthSessionRequest,
};
use openstack_keystone_core_types::auth::IdentityInfo;
use openstack_keystone_core_types::identity::{
    Domain as IdentityDomain, UserPasswordAuthRequestBuilder,
};
use openstack_keystone_core_types::oauth2_client::GrantType;
use openstack_keystone_core_types::oauth2_session::PreAuthSession;

use crate::api::common::PeerAddr;
use crate::audit::{CorrelationId, build_initiator_unknown, emit_oauth2_session_event};
use crate::keystone::ServiceState;

const SESSION_COOKIE_NAME: &str = "keystone_oauth2_session";

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(super) struct AuthorizeQuery {
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct LoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct ConsentForm {
    csrf_token: String,
    decision: String,
}

#[derive(Template)]
#[template(path = "oauth2/login.html")]
struct LoginTemplate<'a> {
    client_id: &'a str,
    csrf_token: &'a str,
    error: Option<&'a str>,
    action: String,
}

#[derive(Template)]
#[template(path = "oauth2/consent.html")]
struct ConsentTemplate<'a> {
    client_id: &'a str,
    scopes: &'a [String],
    csrf_token: &'a str,
    action: String,
}

#[derive(Template)]
#[template(path = "oauth2/error.html")]
struct ErrorTemplate<'a> {
    message: &'a str,
}

/// ADR 0026 §8: defense-in-depth headers on every server-rendered OP
/// response (HTML pages and the redirects between them alike).
fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("0"),
    );
    response
}

fn error_page(status: StatusCode, message: &str) -> Response {
    let body = ErrorTemplate { message }
        .render()
        .unwrap_or_else(|_| message.to_string());
    security_headers((status, Html(body)).into_response())
}

fn too_many_requests(retry_after: u64) -> Response {
    let mut response = error_page(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, retry_after.into());
    response
}

/// Append query parameters to `redirect_uri` and return a
/// security-headers-wrapped 303 See Other. Empty values are omitted (e.g. an
/// absent `state`).
fn redirect_with_params(redirect_uri: &str, pairs: &[(&str, &str)]) -> Response {
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    {
        let mut qp = url.query_pairs_mut();
        for (key, value) in pairs {
            if !value.is_empty() {
                qp.append_pair(key, value);
            }
        }
    }
    security_headers(Redirect::to(url.as_str()).into_response())
}

fn redirect_with_error(
    redirect_uri: &str,
    state_param: &str,
    error: &str,
    description: &str,
) -> Response {
    redirect_with_params(
        redirect_uri,
        &[
            ("error", error),
            ("error_description", description),
            ("state", state_param),
        ],
    )
}

fn redirect_with_code(redirect_uri: &str, code: &str, state_param: &str) -> Response {
    redirect_with_params(redirect_uri, &[("code", code), ("state", state_param)])
}

/// CSRF token derivation (ADR 0026 §8):
/// `HMAC-SHA256(server_side_session_secret, session_id || state ||
/// code_challenge)`. `state`/`code_challenge` are attacker-choosable (whoever
/// initiates `/authorize` may not be the victim), so the secret half of the
/// input -- generated server-side and never sent to the client in cleartext --
/// is what an attacker crafting a link for a victim to click cannot supply.
fn compute_csrf_token(session: &PreAuthSession) -> Option<String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(session.server_side_session_secret.as_bytes()).ok()?;
    mac.update(session.session_id.as_bytes());
    mac.update(session.state.as_bytes());
    mac.update(session.code_challenge.as_bytes());
    Some(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn verify_csrf_token(session: &PreAuthSession, presented: &str) -> bool {
    compute_csrf_token(session).is_some_and(|expected| constant_time_eq(&expected, presented))
}

fn is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
}

fn session_cookie(session_id: String, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, session_id))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .build()
}

fn render_login(domain_id: &str, session: &PreAuthSession, error: Option<&str>) -> Response {
    let Some(csrf_token) = compute_csrf_token(session) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let body = match (LoginTemplate {
        client_id: &session.client_id,
        csrf_token: &csrf_token,
        error,
        action: format!("/v4/oauth2/{domain_id}/authorize/login"),
    })
    .render()
    {
        Ok(body) => body,
        Err(_) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    security_headers((StatusCode::OK, Html(body)).into_response())
}

fn render_consent(domain_id: &str, session: &PreAuthSession) -> Response {
    let Some(csrf_token) = compute_csrf_token(session) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let body = match (ConsentTemplate {
        client_id: &session.client_id,
        scopes: &session.scope,
        csrf_token: &csrf_token,
        action: format!("/v4/oauth2/{domain_id}/authorize/consent"),
    })
    .render()
    {
        Ok(body) => body,
        Err(_) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    security_headers((StatusCode::OK, Html(body)).into_response())
}

/// `GET /v4/oauth2/{domain_id}/authorize` (RFC 6749 §4.1.1, ADR 0026 §10
/// Phase 4).
#[utoipa::path(
    get,
    path = "/{domain_id}/authorize",
    operation_id = "/oauth2:authorize",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        AuthorizeQuery,
    ),
    responses(
        (status = OK, description = "Login form rendered", content_type = "text/html"),
        (status = SEE_OTHER, description = "Redirect back to the client with a code or error"),
        (status = BAD_REQUEST, description = "Malformed request or unregistered redirect_uri"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::authorize",
    level = "debug",
    skip(state, query),
    err(Debug)
)]
pub(super) async fn authorize(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, std::convert::Infallible> {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Ok(too_many_requests(retry_after.as_secs()));
    }

    let Some(response_type) = query.response_type.as_deref() else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "missing required parameter: response_type",
        ));
    };
    if response_type != "code" {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "unsupported response_type; only `code` is supported",
        ));
    }
    let Some(client_id) = query.client_id.clone() else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "missing required parameter: client_id",
        ));
    };

    let exec = ExecutionContext::internal(&state);
    let client = match state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &client_id)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 client lookup failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };
    let Some(client) =
        client.filter(|c| c.domain_id == domain_id && c.enabled && c.deleted_at.is_none())
    else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "unknown or disabled client",
        ));
    };
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "client is not authorized for the authorization_code grant",
        ));
    }

    let Some(redirect_uri) = query.redirect_uri.clone() else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "missing required parameter: redirect_uri",
        ));
    };
    // Open-redirect defense (ADR 0026 §1 Threat Model item 2): never
    // redirect to an unvalidated URI. Every error above this point renders
    // directly; every error below it is delivered via redirect.
    if !client.redirect_uris.iter().any(|u| u == &redirect_uri) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "redirect_uri is not registered for this client",
        ));
    }

    let state_param = query.state.clone().unwrap_or_default();

    let Some(code_challenge) = query.code_challenge.clone() else {
        return Ok(redirect_with_error(
            &redirect_uri,
            &state_param,
            "invalid_request",
            "missing code_challenge",
        ));
    };
    let code_challenge_method = query.code_challenge_method.clone().unwrap_or_default();
    if code_challenge_method != "S256" {
        // PKCE is mandatory and S256-only (ADR 0026 §1) -- not just for
        // public clients.
        return Ok(redirect_with_error(
            &redirect_uri,
            &state_param,
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }

    let requested_scope: Vec<String> = query
        .scope
        .clone()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    const DISPLAY_SCOPES: &[&str] = &["openid", "profile", "email"];
    for s in &requested_scope {
        if s == "openstack:api" {
            return Ok(redirect_with_error(
                &redirect_uri,
                &state_param,
                "invalid_scope",
                "openstack:api is not yet supported on the authorization_code grant",
            ));
        }
        if !DISPLAY_SCOPES.contains(&s.as_str()) || !client.allowed_scopes.iter().any(|a| a == s) {
            return Ok(redirect_with_error(
                &redirect_uri,
                &state_param,
                "invalid_scope",
                "requested scope exceeds the client's allowed_scopes",
            ));
        }
    }

    let session = match state
        .provider
        .get_oauth2_session_provider()
        .start_pre_auth_session(
            &state,
            StartPreAuthSessionRequest {
                domain_id: domain_id.clone(),
                client_id: client.client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                scope: requested_scope,
                state: state_param.clone(),
                code_challenge,
                code_challenge_method,
                nonce: query.nonce.clone(),
            },
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 pre-auth session creation failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        &correlation_id.0,
        "authorize",
        build_initiator_unknown(),
        &client.client_id,
        "attempt",
        None,
    );

    let jar = CookieJar::new().add(session_cookie(
        session.session_id.clone(),
        is_https(&headers),
    ));
    let response = render_login(&domain_id, &session, None);
    Ok((jar, response).into_response())
}

/// `POST /v4/oauth2/{domain_id}/authorize/login`.
#[utoipa::path(
    post,
    path = "/{domain_id}/authorize/login",
    operation_id = "/oauth2:authorize_login",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Consent form rendered, or login form re-rendered on failure", content_type = "text/html"),
        (status = SEE_OTHER, description = "Pre-authorized client: redirected straight to the RP with a code"),
        (status = BAD_REQUEST, description = "Missing/expired session or invalid CSRF token"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::authorize_login",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn authorize_login(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response, std::convert::Infallible> {
    // §7.B "Post-Lookup User Throttle for Browser /authorize" step 1: global
    // per-IP limiter, before any password hashing work. Step 3 (per-user
    // throttle, applied only after account existence is confirmed) is
    // already implemented inside `authenticate_by_password` itself
    // (Invariant 8), shared with the v3 password login path.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Ok(too_many_requests(retry_after.as_secs()));
    }

    let Some(session_id) = jar.get(SESSION_COOKIE_NAME).map(|c| c.value().to_string()) else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "session expired; please restart sign-in",
        ));
    };
    let session = match state
        .provider
        .get_oauth2_session_provider()
        .get_pre_auth_session(&state, &session_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(error_page(
                StatusCode::BAD_REQUEST,
                "session expired; please restart sign-in",
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 pre-auth session lookup failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    if !verify_csrf_token(&session, &form.csrf_token) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired form submission; please restart sign-in",
        ));
    }

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
                &session,
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
            tracing::debug!(error = %e, "oauth2 authorize login failed");
            emit_oauth2_session_event(
                &state.audit_dispatcher,
                &correlation_id.0,
                "authenticate",
                build_initiator_unknown(),
                &session.client_id,
                "failure",
                Some("invalid username or password".to_string()),
            );
            return Ok(render_login(
                &domain_id,
                &session,
                Some("invalid username or password"),
            ));
        }
    };

    let IdentityInfo::Principal(pinfo) = &auth_result.principal.identity else {
        return Ok(error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        ));
    };
    let user_id = pinfo.id.clone();
    let now = chrono::Utc::now().timestamp();

    let session = match state
        .provider
        .get_oauth2_session_provider()
        .mark_authenticated(&state, &session_id, &user_id, now)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 pre-auth session update failed");
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
        build_initiator_unknown(),
        &session.client_id,
        "success",
        None,
    );

    // Re-fetch the client for the `pre_authorized` consent-skip check (ADR
    // 0026 §7.C's invariant applied here too: a `pre_authorized` client
    // never has `openstack:api` in `allowed_scopes`, enforced at CRUD
    // time, so skipping consent here cannot silently grant OpenStack
    // authorization).
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &session.client_id)
        .await
        .ok()
        .flatten();
    if client.as_ref().is_some_and(|c| c.pre_authorized) {
        return Ok(finish_consent(&state, &domain_id, &session, true, &correlation_id.0).await);
    }

    Ok(render_consent(&domain_id, &session))
}

/// `POST /v4/oauth2/{domain_id}/authorize/consent`.
#[utoipa::path(
    post,
    path = "/{domain_id}/authorize/consent",
    operation_id = "/oauth2:authorize_consent",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = SEE_OTHER, description = "Redirect back to the client with a code or error"),
        (status = BAD_REQUEST, description = "Missing/expired session, not signed in, or invalid CSRF token"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::authorize_consent",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn authorize_consent(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Form(form): Form<ConsentForm>,
) -> Result<Response, std::convert::Infallible> {
    let Some(session_id) = jar.get(SESSION_COOKIE_NAME).map(|c| c.value().to_string()) else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "session expired; please restart sign-in",
        ));
    };
    let session = match state
        .provider
        .get_oauth2_session_provider()
        .get_pre_auth_session(&state, &session_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(error_page(
                StatusCode::BAD_REQUEST,
                "session expired; please restart sign-in",
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 pre-auth session lookup failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    if !verify_csrf_token(&session, &form.csrf_token) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired form submission; please restart sign-in",
        ));
    }
    if session.user_id.is_none() {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "not signed in; please restart sign-in",
        ));
    }

    let granted = form.decision == "allow";
    Ok(finish_consent(&state, &domain_id, &session, granted, &correlation_id.0).await)
}

/// Complete the flow after consent is known (explicit consent POST, or the
/// `pre_authorized` skip from `authorize_login`): mint the code and
/// redirect, or redirect with `access_denied`.
async fn finish_consent(
    state: &ServiceState,
    domain_id: &str,
    session: &PreAuthSession,
    granted: bool,
    correlation_id: &str,
) -> Response {
    // Single-flight: the pre-auth session is consumed either way.
    let _ = state
        .provider
        .get_oauth2_session_provider()
        .complete_pre_auth_session(state, &session.session_id)
        .await;

    if !granted {
        emit_oauth2_session_event(
            &state.audit_dispatcher,
            correlation_id,
            "authorize",
            build_initiator_unknown(),
            &session.client_id,
            "failure",
            Some("consent denied".to_string()),
        );
        return redirect_with_error(
            &session.redirect_uri,
            &session.state,
            "access_denied",
            "user denied the request",
        );
    }

    let (Some(user_id), Some(auth_time)) = (session.user_id.clone(), session.auth_time) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "not signed in; please restart sign-in",
        );
    };

    let code = match state
        .provider
        .get_oauth2_session_provider()
        .issue_authorization_code(
            state,
            IssueAuthorizationCodeRequest {
                domain_id: domain_id.to_string(),
                client_id: session.client_id.clone(),
                user_id,
                redirect_uri: session.redirect_uri.clone(),
                code_challenge: session.code_challenge.clone(),
                code_challenge_method: session.code_challenge_method.clone(),
                scope: session.scope.clone(),
                nonce: session.nonce.clone(),
                auth_time,
                amr: vec!["pwd".to_string()],
            },
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 authorization code issuance failed");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "authorize",
        build_initiator_unknown(),
        &session.client_id,
        "success",
        None,
    );

    redirect_with_code(&session.redirect_uri, &code, &session.state)
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

    use openstack_keystone_core_types::auth::AuthenticationError;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthenticationResultBuilder, AuthzInfoBuilder, IdentityInfo,
        PrincipalIdentityInfoBuilder, PrincipalInfo, ScopeInfo,
    };
    use openstack_keystone_core_types::identity::IdentityProviderError;
    use openstack_keystone_core_types::oauth2_client as provider_types;
    use openstack_keystone_core_types::oauth2_session::PreAuthSession;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn authz_client() -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![provider_types::GrantType::AuthorizationCode],
            require_pkce: true,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    const AUTHZ_QS: &str = "response_type=code&client_id=client-1&redirect_uri=https://rp.example.com/callback&scope=openid&state=xyz&code_challenge=abc&code_challenge_method=S256";

    fn get_request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("GET")
            .body(Body::empty())
            .unwrap()
    }

    async fn text_body(response: axum::response::Response) -> String {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_authorize_missing_response_type_is_bad_request() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(get_request("/domain-1/authorize?client_id=client-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_authorize_unregistered_redirect_uri_never_redirects() {
        let client = authz_client();
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(get_request(
                "/domain-1/authorize?response_type=code&client_id=client-1&redirect_uri=https://evil.example.com/cb",
            ))
            .await
            .unwrap();
        // Never a redirect: an unvalidated redirect_uri must render an
        // error page directly (open-redirect defense).
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::LOCATION).is_none());
    }

    #[tokio::test]
    async fn test_authorize_missing_pkce_redirects_with_invalid_request() {
        let client = authz_client();
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(get_request(
                "/domain-1/authorize?response_type=code&client_id=client-1&redirect_uri=https://rp.example.com/callback",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://rp.example.com/callback"));
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_authorize_openstack_api_scope_redirects_with_invalid_scope() {
        let client = authz_client();
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(get_request(
                "/domain-1/authorize?response_type=code&client_id=client-1&redirect_uri=https://rp.example.com/callback&scope=openstack:api&code_challenge=abc&code_challenge_method=S256",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("error=invalid_scope"));
    }

    #[tokio::test]
    async fn test_authorize_success_renders_login_and_sets_cookie() {
        let client = authz_client();
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_start_pre_auth_session()
            .returning(|_, req| {
                Ok(PreAuthSession {
                    session_id: "session-1".to_string(),
                    domain_id: req.domain_id,
                    client_id: req.client_id,
                    redirect_uri: req.redirect_uri,
                    scope: req.scope,
                    state: req.state,
                    code_challenge: req.code_challenge,
                    code_challenge_method: req.code_challenge_method,
                    nonce: req.nonce,
                    server_side_session_secret: "secret".to_string(),
                    user_id: None,
                    auth_time: None,
                    consent_granted: None,
                    created_at: 0,
                    expires_at: 1_000_000_000,
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(get_request(&format!("/domain-1/authorize?{AUTHZ_QS}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("keystone_oauth2_session=session-1"));
        assert!(set_cookie.to_lowercase().contains("httponly"));
        let body = text_body(response).await;
        assert!(body.contains("client-1"));
    }

    fn sample_session() -> PreAuthSession {
        PreAuthSession {
            session_id: "session-1".to_string(),
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            redirect_uri: "https://rp.example.com/callback".to_string(),
            scope: vec!["openid".to_string()],
            state: "xyz".to_string(),
            code_challenge: "abc".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: None,
            server_side_session_secret: "secret".to_string(),
            user_id: None,
            auth_time: None,
            consent_granted: None,
            created_at: 0,
            expires_at: 1_000_000_000,
        }
    }

    fn login_post_request(body: &str) -> Request<Body> {
        Request::builder()
            .uri("/domain-1/authorize/login")
            .method("POST")
            .header(header::COOKIE, "keystone_oauth2_session=session-1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_authorize_login_bad_csrf_token_is_bad_request() {
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(|_, _| Ok(Some(sample_session())));
        let provider = Provider::mocked_builder().mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(login_post_request(
                "csrf_token=wrong&username=alice&password=pass",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn csrf_for(session: &PreAuthSession) -> String {
        super::compute_csrf_token(session).unwrap()
    }

    #[tokio::test]
    async fn test_authorize_login_wrong_password_rerenders_login() {
        let session = sample_session();
        let csrf = csrf_for(&session);

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _| {
                Err(IdentityProviderError::Authentication {
                    source: AuthenticationError::UserNameOrPasswordWrong,
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
            .oneshot(login_post_request(&format!(
                "csrf_token={csrf}&username=alice&password=wrong"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text_body(response).await;
        assert!(body.contains("invalid username or password"));
    }

    fn successful_password_auth_result() -> openstack_keystone_core_types::auth::AuthenticationResult
    {
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::Principal(
                    PrincipalIdentityInfoBuilder::default()
                        .id("user-1")
                        .resolved_user_name("alice")
                        .issuer("local")
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

    #[tokio::test]
    async fn test_authorize_login_success_renders_consent() {
        let session = sample_session();
        let csrf = csrf_for(&session);

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        session_mock
            .expect_mark_authenticated()
            .returning(|_, _, _, _| Ok(sample_session()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _| Ok(successful_password_auth_result()));

        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(authz_client())));

        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(login_post_request(&format!(
                "csrf_token={csrf}&username=alice&password=pass"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text_body(response).await;
        assert!(body.contains("openid"));
    }

    fn consent_post_request(body: &str) -> Request<Body> {
        Request::builder()
            .uri("/domain-1/authorize/consent")
            .method("POST")
            .header(header::COOKIE, "keystone_oauth2_session=session-1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn authenticated_session() -> PreAuthSession {
        PreAuthSession {
            user_id: Some("user-1".to_string()),
            auth_time: Some(1000),
            ..sample_session()
        }
    }

    #[tokio::test]
    async fn test_authorize_consent_deny_redirects_with_access_denied() {
        let session = authenticated_session();
        let csrf = csrf_for(&session);

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        session_mock
            .expect_complete_pre_auth_session()
            .returning(|_, _| Ok(()));

        let provider = Provider::mocked_builder().mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(consent_post_request(&format!(
                "csrf_token={csrf}&decision=deny"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("error=access_denied"));
    }

    #[tokio::test]
    async fn test_authorize_consent_allow_redirects_with_code() {
        let session = authenticated_session();
        let csrf = csrf_for(&session);

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        session_mock
            .expect_complete_pre_auth_session()
            .returning(|_, _| Ok(()));
        session_mock
            .expect_issue_authorization_code()
            .returning(|_, _| Ok("issued-code-1".to_string()));

        let provider = Provider::mocked_builder().mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(consent_post_request(&format!(
                "csrf_token={csrf}&decision=allow"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("code=issued-code-1"));
        assert!(location.contains("state=xyz"));
    }
}
