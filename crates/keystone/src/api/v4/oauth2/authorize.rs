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

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use cadf::Outcome;
use cadf::OutcomeReason;
use secrecy::SecretString;
use serde::Deserialize;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_session::{
    IssueAuthorizationCodeRequest, StartPreAuthSessionRequest,
};
use openstack_keystone_core_types::auth::IdentityInfo;
use openstack_keystone_core_types::identity::{
    Domain as IdentityDomain, UserPasswordAuthRequestBuilder,
};
use openstack_keystone_core_types::oauth2_client::{GrantType, OAuth2ClientResource};
use openstack_keystone_core_types::oauth2_session::PreAuthSession;

use super::federated::{idp_views, login_idps, redirect_to_upstream};
use super::html::{
    client_view, consent_page, error_page, fetch_client, login_page, mfa_page, security_headers,
    too_many_requests, view_of,
};
use super::renderer::{ClientView, ConsentCtx, IdpView, LoginCtx, MfaCtx};
use crate::api::common::PeerAddr;
use crate::audit::{
    CorrelationId, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_session_event,
};
use crate::keystone::ServiceState;

pub(super) const SESSION_COOKIE_NAME: &str = "keystone_oauth2_session";

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
    /// Skip the login chooser and go straight to this upstream identity
    /// provider. Only a registered, enabled IdP of the domain is honoured;
    /// anything else is ignored.
    #[serde(default)]
    idp_hint: Option<String>,
    /// Maximum authentication age in seconds (OIDC Core §3.1.2.1).
    #[serde(default)]
    max_age: Option<String>,
    /// Space-separated `none`, `login`, `consent`, `select_account`.
    #[serde(default)]
    prompt: Option<String>,
    /// Prefills the username field of the login form.
    #[serde(default)]
    login_hint: Option<String>,
}

/// The parsed `prompt` request parameter (OIDC Core §3.1.2.1).
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Prompt {
    pub(super) none: bool,
    pub(super) login: bool,
    pub(super) select_account: bool,
    pub(super) consent: bool,
}

/// Parse `prompt`. `none` must not be combined with any other value; an
/// unknown value is an error.
pub(super) fn parse_prompt(raw: Option<&str>) -> Result<Prompt, &'static str> {
    let mut prompt = Prompt::default();
    let mut count = 0;
    for value in raw.unwrap_or_default().split_whitespace() {
        count += 1;
        match value {
            "none" => prompt.none = true,
            "login" => prompt.login = true,
            "select_account" => prompt.select_account = true,
            // Ask even when a remembered consent would cover the request.
            "consent" => prompt.consent = true,
            _ => return Err("unsupported prompt value"),
        }
    }
    if prompt.none && count > 1 {
        return Err("prompt=none must not be combined with other values");
    }
    Ok(prompt)
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
    /// Present (any value) when the "remember" checkbox was ticked.
    #[serde(default)]
    remember: Option<String>,
}

/// Append query parameters to `redirect_uri` and return a
/// security-headers-wrapped 303 See Other. Empty values are omitted (e.g. an
/// absent `state`).
pub(super) fn redirect_with_params(redirect_uri: &str, pairs: &[(&str, &str)]) -> Response {
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
pub(super) fn compute_csrf_token(session: &PreAuthSession) -> Option<String> {
    super::html::compute_csrf_token(
        &session.server_side_session_secret,
        &[&session.session_id, &session.state, &session.code_challenge],
    )
}

pub(super) fn verify_csrf_token(session: &PreAuthSession, presented: &str) -> bool {
    compute_csrf_token(session)
        .is_some_and(|expected| super::html::constant_time_eq(&expected, presented))
}

pub(super) async fn cookie_secure(state: &ServiceState, headers: &HeaderMap) -> bool {
    crate::api::common::oauth2_cookie_secure(state, headers).await
}

pub(super) fn session_cookie(session_id: String, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, session_id))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .build()
}

pub(super) fn render_login(
    domain_id: &str,
    session: &PreAuthSession,
    client: &ClientView,
    error: Option<&str>,
    idps: Vec<IdpView>,
) -> Response {
    render_login_hinted(domain_id, session, client, error, idps, None)
}

/// [`render_login`] with the RP's `login_hint` prefilled into the username.
fn render_login_hinted(
    domain_id: &str,
    session: &PreAuthSession,
    client: &ClientView,
    error: Option<&str>,
    idps: Vec<IdpView>,
    login_hint: Option<&str>,
) -> Response {
    let Some(csrf_token) = compute_csrf_token(session) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    login_page(&LoginCtx {
        client: client.clone(),
        csrf_token,
        error: error.map(str::to_string),
        action: format!("/v4/oauth2/{domain_id}/authorize/login"),
        idps,
        federated_action: format!("/v4/oauth2/{domain_id}/authorize/federated"),
        login_hint: login_hint
            .filter(|h| !h.is_empty())
            .map(|h| h.chars().take(256).collect()),
    })
}

pub(super) fn render_mfa(
    domain_id: &str,
    session: &PreAuthSession,
    client: &ClientView,
    error: Option<&str>,
) -> Response {
    let Some(csrf_token) = compute_csrf_token(session) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    mfa_page(&MfaCtx {
        client: client.clone(),
        csrf_token,
        error: error.map(str::to_string),
        action: format!("/v4/oauth2/{domain_id}/authorize/mfa"),
    })
}

fn render_consent(
    domain_id: &str,
    session: &PreAuthSession,
    client: &ClientView,
    remember: Option<bool>,
) -> Response {
    let Some(csrf_token) = compute_csrf_token(session) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    consent_page(&ConsentCtx {
        client: client.clone(),
        scopes: session.scope.clone(),
        csrf_token,
        action: format!("/v4/oauth2/{domain_id}/authorize/consent"),
        remember,
    })
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
        (status = SERVICE_UNAVAILABLE, description = "`public_endpoint` is not configured"),
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
    jar: CookieJar,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, std::convert::Infallible> {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Ok(too_many_requests(retry_after.as_secs()));
    }

    if !crate::api::common::oauth2_issuer_is_trusted(&state).await {
        tracing::error!(
            "OAuth2 /authorize refused: [DEFAULT] public_endpoint is not set \
             (set it, or [oauth2] allow_host_header_issuer = true for development only)"
        );
        return Ok(error_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "the OAuth2 provider is not configured with a public endpoint",
        ));
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

    let prompt = match parse_prompt(query.prompt.as_deref()) {
        Ok(p) => p,
        Err(message) => {
            return Ok(redirect_with_error(
                &redirect_uri,
                &state_param,
                "invalid_request",
                message,
            ));
        }
    };
    let max_age = match query.max_age.as_deref().map(str::parse::<i64>) {
        None => None,
        Some(Ok(n)) if n >= 0 => Some(n),
        Some(_) => {
            return Ok(redirect_with_error(
                &redirect_uri,
                &state_param,
                "invalid_request",
                "max_age must be a non-negative integer",
            ));
        }
    };

    // An existing SSO session is reused unless the request forces a fresh
    // login (`prompt=login|select_account`, or `max_age` older than the
    // login; `max_age=0` always forces one).
    let now = chrono::Utc::now().timestamp();
    let sso = super::sso::current(&state, &jar, &domain_id).await;
    let force_login = prompt.login
        || prompt.select_account
        || max_age.is_some_and(|m| m == 0 || sso.as_ref().is_some_and(|s| now - s.auth_time > m));
    let sso = sso.filter(|_| !force_login);
    if prompt.none {
        // Never render HTML: either the request is satisfiable silently or
        // it is answered with an error redirect, and no cookie is set.
        if sso.is_none() {
            return Ok(redirect_with_error(
                &redirect_uri,
                &state_param,
                "login_required",
                "the user is not signed in",
            ));
        }
        let remembered = match &sso {
            Some(s) if !client.pre_authorized => {
                super::consent::is_covered(
                    &state,
                    &domain_id,
                    &s.user_id,
                    &client.client_id,
                    &requested_scope,
                )
                .await
            }
            _ => false,
        };
        if !client.pre_authorized && !remembered {
            return Ok(redirect_with_error(
                &redirect_uri,
                &state_param,
                "consent_required",
                "the user has not consented to this client",
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
                force_consent: prompt.consent,
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
        Outcome::Pending,
        None,
    );

    if let Some(sso) = sso {
        let session = match state
            .provider
            .get_oauth2_session_provider()
            .mark_authenticated_by_sso(&state, &session.session_id, &sso)
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
            build_initiator_from_user_id(&sso.user_id, &domain_id),
            &session.client_id,
            Outcome::Success,
            None,
        );
        let response = after_authentication(
            &state,
            &domain_id,
            &session,
            Some(&client),
            &correlation_id.0,
        )
        .await;
        let jar = CookieJar::new().add(session_cookie(
            session.session_id.clone(),
            cookie_secure(&state, &headers).await,
        ));
        return Ok((jar, response).into_response());
    }

    let jar = CookieJar::new().add(session_cookie(
        session.session_id.clone(),
        cookie_secure(&state, &headers).await,
    ));
    let client_ui = client_view(&state, &session.client_id).await;
    let idps = login_idps(&state, &domain_id).await;
    if let Some(hint) = query.idp_hint.as_deref()
        && let Some(idp) = idps.iter().find(|idp| idp.id == hint).cloned()
    {
        let response = match redirect_to_upstream(
            &state,
            &headers,
            &domain_id,
            &session.session_id,
            idp,
        )
        .await
        {
            Ok(redirect) => redirect,
            Err(message) => render_login(
                &domain_id,
                &session,
                &client_ui,
                Some(message),
                idp_views(&idps),
            ),
        };
        return Ok((jar, response).into_response());
    }
    let response = render_login_hinted(
        &domain_id,
        &session,
        &client_ui,
        None,
        idp_views(&idps),
        query.login_hint.as_deref(),
    );
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

    // A session only belongs to the domain it was started in.
    if session.domain_id != domain_id {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "session expired; please restart sign-in",
        ));
    }
    if !verify_csrf_token(&session, &form.csrf_token) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired form submission; please restart sign-in",
        ));
    }

    let client = fetch_client(&state, &session.client_id).await;
    let client_ui = view_of(client.as_ref(), &session.client_id);
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
                &client_ui,
                Some("invalid username or password"),
                idp_views(&login_idps(&state, &domain_id).await),
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
                Outcome::Failure,
                Some(OutcomeReason::literal("InvalidCredentials")),
            );
            return Ok(render_login(
                &domain_id,
                &session,
                &client_ui,
                Some("invalid username or password"),
                idp_views(&login_idps(&state, &domain_id).await),
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
                .begin_mfa(&state, &session_id, &user_id, factors)
                .await
            {
                Ok(pending) => render_mfa(&domain_id, &pending, &client_ui, None),
                Err(e) => {
                    tracing::warn!(error = %e, "oauth2 pre-auth session update failed");
                    error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                }
            },
        );
    }

    let session = match state
        .provider
        .get_oauth2_session_provider()
        .mark_authenticated(&state, &session_id, &user_id, now, super::mfa::amr_for(&[]))
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
        build_initiator_from_user_id(&user_id, &session.domain_id),
        &session.client_id,
        Outcome::Success,
        None,
    );

    let response = after_authentication(
        &state,
        &domain_id,
        &session,
        client.as_ref(),
        &correlation_id.0,
    )
    .await;
    Ok(super::sso::attach(&state, &headers, &jar, &session, response).await)
}

/// Everything after a completed login (password and any second factor):
/// skip consent for `pre_authorized` clients, otherwise render it.
pub(super) async fn after_authentication(
    state: &ServiceState,
    domain_id: &str,
    session: &PreAuthSession,
    client: Option<&OAuth2ClientResource>,
    correlation_id: &str,
) -> Response {
    // `pre_authorized` consent-skip check (ADR 0026 §7.C's invariant applied
    // here too: a `pre_authorized` client never has `openstack:api` in
    // `allowed_scopes`, enforced at CRUD time, so skipping consent here
    // cannot silently grant OpenStack authorization).
    if client.is_some_and(|c| c.pre_authorized) {
        return finish_consent(state, domain_id, session, true, correlation_id).await;
    }

    // A remembered consent that covers the request replaces the page, unless
    // the request asked for `prompt=consent`.
    if !session.force_consent
        && let (Some(c), Some(user_id)) = (client, session.user_id.as_deref())
        && super::consent::is_covered(state, domain_id, user_id, &c.client_id, &session.scope).await
    {
        return finish_consent(state, domain_id, session, true, correlation_id).await;
    }

    let client_ui = view_of(client, &session.client_id);
    let remember = super::consent::remember_choice(client, &session.scope);
    render_consent(domain_id, session, &client_ui, remember)
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

    // A session only belongs to the domain it was started in.
    if session.domain_id != domain_id {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "session expired; please restart sign-in",
        ));
    }
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
    if granted
        && form.remember.is_some()
        && let Some(user_id) = session.user_id.as_deref()
    {
        let client = state
            .provider
            .get_oauth2_client_provider()
            .get_by_client_id(&ExecutionContext::internal(&state), &session.client_id)
            .await
            .ok()
            .flatten();
        super::consent::remember(
            &state,
            client.as_ref(),
            &domain_id,
            user_id,
            &session.scope,
            &correlation_id.0,
        )
        .await;
    }
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
            // A denial is the user's decision; attribute it to them the
            // same way `device.rs`'s `finish_decision` does.
            session
                .user_id
                .as_deref()
                .map_or_else(build_initiator_unknown, |user_id| {
                    build_initiator_from_user_id(user_id, domain_id)
                }),
            &session.client_id,
            Outcome::Failure,
            Some(OutcomeReason::literal("ConsentDenied")),
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
                user_id: user_id.clone(),
                redirect_uri: session.redirect_uri.clone(),
                code_challenge: session.code_challenge.clone(),
                code_challenge_method: session.code_challenge_method.clone(),
                scope: session.scope.clone(),
                nonce: session.nonce.clone(),
                auth_time,
                amr: if session.amr.is_empty() {
                    vec!["pwd".to_string()]
                } else {
                    session.amr.clone()
                },
                upstream: session.upstream.clone(),
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
        build_initiator_from_user_id(&user_id, domain_id),
        &session.client_id,
        Outcome::Success,
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
        PrincipalInfo, ScopeInfo, UserIdentityInfoBuilder,
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
            post_logout_redirect_uris: Default::default(),
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
            name: "Example App".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
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
                    pending_upstream: None,
                    force_consent: false,
                    upstream: None,
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
                    amr: vec![],
                    pending_user_id: None,
                    pending_factors: vec![],
                    mfa_attempts: 0,
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
        // The registered name is shown, not the raw client id.
        assert!(body.contains("Example App"));
        assert!(!body.contains("client-1"));
    }

    #[tokio::test]
    async fn test_authorize_unset_public_endpoint_is_service_unavailable() {
        let state = crate::api::tests::get_mocked_state_with_config(
            Provider::mocked_builder(),
            true,
            None,
            openstack_keystone_config::Config::default(),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(get_request(&format!("/domain-1/authorize?{AUTHZ_QS}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    fn sample_session() -> PreAuthSession {
        PreAuthSession {
            pending_upstream: None,
            force_consent: false,
            upstream: None,
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
            amr: vec![],
            pending_user_id: None,
            pending_factors: vec![],
            mfa_attempts: 0,
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

        let client = authz_client();
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_oauth2_client(client_mock)
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
            .withf(|_, _, user_id, _, amr| user_id == "user-1" && *amr == ["pwd"])
            .returning(|_, _, _, _, _| Ok(sample_session()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _| Ok(successful_password_auth_result()));
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
            .returning(|_, _, _| Ok(Vec::new()));

        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(authz_client())));

        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_credential(credential_mock)
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

    #[tokio::test]
    async fn test_login_and_consent_reject_a_session_of_another_domain() {
        // The session belongs to domain-1; the other domain's path must not
        // authenticate against it, nor store a consent for it. No other
        // provider is mocked, so reaching one would panic.
        let session = sample_session();
        let csrf = csrf_for(&session);
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        for (uri, body) in [
            (
                "/domain-2/authorize/login",
                format!("csrf_token={csrf}&username=alice&password=pass"),
            ),
            (
                "/domain-2/authorize/consent",
                format!("csrf_token={csrf}&decision=allow&remember=on"),
            ),
        ] {
            let request = Request::builder()
                .uri(uri)
                .method("POST")
                .header(header::COOKIE, "keystone_oauth2_session=session-1")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap();
            let response = api.as_service().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    #[test]
    fn test_render_login_and_consent_headers() {
        let session = sample_session();
        for response in [
            super::render_login(
                "domain-1",
                &session,
                &super::ClientView::from_id("c"),
                None,
                Vec::new(),
            ),
            super::render_consent("domain-1", &session, &super::ClientView::from_id("c"), None),
        ] {
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["pragma"], "no-cache");
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        }
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
        // The 303 Location carries the authorization code in the query
        // string, so it must not be cached.
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("code=issued-code-1"));
        assert!(location.contains("state=xyz"));
    }

    // ---- second-factor (TOTP) step ----

    fn totp_user_mocks() -> (
        MockIdentityProvider,
        crate::credential::MockCredentialProvider,
    ) {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .returning(|_, _| Ok(successful_password_auth_result()));
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
        (identity_mock, credential_mock)
    }

    fn pending_session(attempts: u32) -> PreAuthSession {
        PreAuthSession {
            pending_user_id: Some("user-1".into()),
            pending_factors: vec!["totp".into()],
            mfa_attempts: attempts,
            ..sample_session()
        }
    }

    fn mfa_post_request(body: &str) -> Request<Body> {
        Request::builder()
            .uri("/domain-1/authorize/mfa")
            .method("POST")
            .header(header::COOKIE, "keystone_oauth2_session=session-1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn client_mock() -> MockOauth2ClientProvider {
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(authz_client())));
        client_mock
    }

    #[tokio::test]
    async fn test_login_with_totp_credential_renders_mfa_and_does_not_sign_in() {
        let session = sample_session();
        let csrf = csrf_for(&session);

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        // `mark_authenticated` has no expectation: calling it would panic.
        session_mock
            .expect_begin_mfa()
            .withf(|_, _, user_id, factors| user_id == "user-1" && *factors == ["totp"])
            .returning(|_, _, _, _| Ok(pending_session(0)));

        let (identity_mock, credential_mock) = totp_user_mocks();
        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_credential(credential_mock)
            .mock_oauth2_client(client_mock());
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
        assert!(body.contains("name=\"passcode\""));
        assert!(!body.contains("Allow"));
    }

    #[tokio::test]
    async fn test_login_fails_closed_when_second_factor_lookup_fails() {
        let session = sample_session();
        let csrf = csrf_for(&session);

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));

        let (identity_mock, _) = totp_user_mocks();
        let mut credential_mock = crate::credential::MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .returning(|_, _, _| {
                Err(openstack_keystone_core_types::credential::CredentialProviderError::CredentialNotFound(
                    "x".into(),
                ))
            });
        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_credential(credential_mock)
            .mock_oauth2_client(client_mock());
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
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_mfa_correct_code_signs_in_with_mfa_amr_and_renders_consent() {
        let session = pending_session(1);
        let csrf = csrf_for(&session);

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        session_mock
            .expect_record_mfa_attempt()
            .times(1)
            .returning(|_, _| Ok(pending_session(1)));
        session_mock
            .expect_mark_authenticated()
            .withf(|_, _, user_id, _, amr| user_id == "user-1" && *amr == ["pwd", "otp", "mfa"])
            .returning(|_, _, _, _, _| Ok(sample_session()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_totp()
            .returning(|_, _| Ok(successful_password_auth_result()));
        let provider = Provider::mocked_builder()
            .mock_oauth2_session(session_mock)
            .mock_identity(identity_mock)
            .mock_oauth2_client(client_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(mfa_post_request(&format!(
                "csrf_token={csrf}&factor=totp&passcode=123456"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text_body(response).await;
        assert!(body.contains("openid"));
        assert!(body.contains("name=\"decision\""));
    }

    #[tokio::test]
    async fn test_mfa_wrong_code_rerenders_and_counts_the_attempt() {
        let session = pending_session(0);
        let csrf = csrf_for(&session);

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        session_mock
            .expect_record_mfa_attempt()
            .times(1)
            .returning(|_, _| Ok(pending_session(1)));

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
            .mock_identity(identity_mock)
            .mock_oauth2_client(client_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(mfa_post_request(&format!(
                "csrf_token={csrf}&factor=totp&passcode=000000"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text_body(response).await;
        assert!(body.contains("invalid verification code"));
        assert!(body.contains("name=\"passcode\""));
    }

    #[tokio::test]
    async fn test_mfa_attempt_budget_exhausted_discards_the_session() {
        let session = pending_session(0);
        let csrf = csrf_for(&session);
        let max = openstack_keystone_config::Oauth2Provider::default().mfa_max_attempts;

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        session_mock
            .expect_record_mfa_attempt()
            .returning(move |_, _| Ok(pending_session(max)));
        session_mock
            .expect_complete_pre_auth_session()
            .times(1)
            .returning(|_, _| Ok(()));

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
            .oneshot(mfa_post_request(&format!(
                "csrf_token={csrf}&factor=totp&passcode=000000"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_mfa_without_pending_factor_or_with_bad_csrf_is_bad_request() {
        // No pending second factor: a password-only session cannot use the step.
        let session = sample_session();
        let csrf = csrf_for(&session);
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(mfa_post_request(&format!(
                "csrf_token={csrf}&factor=totp&passcode=123456"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Wrong CSRF token on a pending session.
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(|_, _| Ok(Some(pending_session(0))));
        let provider = Provider::mocked_builder().mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(mfa_post_request(
                "csrf_token=wrong&factor=totp&passcode=123456",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_consent_cannot_be_reached_while_second_factor_is_pending() {
        let session = pending_session(0);
        let csrf = csrf_for(&session);
        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
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
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
