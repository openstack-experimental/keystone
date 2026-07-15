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

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use secrecy::SecretString;
use serde::Deserialize;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::IdentityInfo;
use openstack_keystone_core_types::identity::{
    Domain as IdentityDomain, UserPasswordAuthRequestBuilder,
};
use openstack_keystone_core_types::oauth2_session::DeviceCodeGrant;

use super::html::{ConsentTemplate, LoginTemplate, error_page, security_headers};
use crate::audit::{CorrelationId, build_initiator_unknown, emit_oauth2_session_event};
use crate::keystone::ServiceState;

const DEVICE_COOKIE_NAME: &str = "keystone_oauth2_device_code";

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

#[derive(Template)]
#[template(path = "oauth2/device_entry.html")]
struct DeviceEntryTemplate<'a> {
    error: Option<&'a str>,
    prefill: &'a str,
    action: String,
}

#[derive(Template)]
#[template(path = "oauth2/device_result.html")]
struct DeviceResultTemplate<'a> {
    granted: bool,
    client_id: &'a str,
}

/// CSRF token derivation, mirroring `authorize.rs`'s but keyed on the
/// device grant's own identifiers instead of a `PreAuthSession`'s.
fn compute_csrf_token(grant: &DeviceCodeGrant) -> Option<String> {
    super::html::compute_csrf_token(
        &grant.server_side_session_secret,
        &[&grant.device_code, &grant.user_code],
    )
}

fn verify_csrf_token(grant: &DeviceCodeGrant, presented: &str) -> bool {
    compute_csrf_token(grant)
        .is_some_and(|expected| super::html::constant_time_eq(&expected, presented))
}

fn is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
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
    let body = match (DeviceEntryTemplate {
        error,
        prefill,
        action: format!("/v4/oauth2/{domain_id}/device"),
    })
    .render()
    {
        Ok(body) => body,
        Err(_) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    security_headers((StatusCode::OK, Html(body)).into_response())
}

fn render_login(
    domain_id: &str,
    client_id: &str,
    grant: &DeviceCodeGrant,
    error: Option<&str>,
) -> Response {
    let Some(csrf_token) = compute_csrf_token(grant) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let body = match (LoginTemplate {
        client_id,
        csrf_token: &csrf_token,
        error,
        action: format!("/v4/oauth2/{domain_id}/device/login"),
    })
    .render()
    {
        Ok(body) => body,
        Err(_) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    security_headers((StatusCode::OK, Html(body)).into_response())
}

fn render_consent(domain_id: &str, client_id: &str, grant: &DeviceCodeGrant) -> Response {
    let Some(csrf_token) = compute_csrf_token(grant) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let body = match (ConsentTemplate {
        client_id,
        scopes: &grant.scope,
        csrf_token: &csrf_token,
        action: format!("/v4/oauth2/{domain_id}/device/consent"),
    })
    .render()
    {
        Ok(body) => body,
        Err(_) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    security_headers((StatusCode::OK, Html(body)).into_response())
}

fn render_result(granted: bool, client_id: &str) -> Response {
    let body = match (DeviceResultTemplate { granted, client_id }).render() {
        Ok(body) => body,
        Err(_) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    security_headers((StatusCode::OK, Html(body)).into_response())
}

async fn client_id_for_display(state: &ServiceState, client_id: &str) -> String {
    // Best-effort display only (the actual grant is already bound to
    // `client_id` in storage); a lookup failure just falls back to the raw
    // ID rather than failing the whole page render.
    let exec = ExecutionContext::internal(state);
    state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, client_id)
        .await
        .ok()
        .flatten()
        .map(|c| c.client_id)
        .unwrap_or_else(|| client_id.to_string())
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
    jar: CookieJar,
    Form(form): Form<DeviceCodeForm>,
) -> Result<Response, std::convert::Infallible> {
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

    let client_id = client_id_for_display(&state, &grant.client_id).await;
    let jar = jar.add(device_cookie(grant.device_code.clone(), is_https(&headers)));
    let response = render_login(&domain_id, &client_id, &grant, None);
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
    correlation_id: CorrelationId,
    jar: CookieJar,
    Form(form): Form<DeviceLoginForm>,
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

    let client_id = client_id_for_display(&state, &grant.client_id).await;

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
                &client_id,
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
                "failure",
                Some("invalid username or password".to_string()),
            );
            return Ok(render_login(
                &domain_id,
                &client_id,
                &grant,
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

    let grant = match state
        .provider
        .get_oauth2_session_provider()
        .mark_device_authenticated(&state, &device_code, &user_id, now, vec!["pwd".to_string()])
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
        build_initiator_unknown(),
        &grant.client_id,
        "success",
        None,
    );

    // `pre_authorized` skips consent only, never login (same invariant as
    // `authorize.rs`): a `pre_authorized` client can never carry
    // `openstack:api` in `allowed_scopes` (enforced at CRUD time), so
    // skipping consent here cannot silently grant OpenStack authorization.
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &grant.client_id)
        .await
        .ok()
        .flatten();
    if client.as_ref().is_some_and(|c| c.pre_authorized) {
        return Ok(finish_decision(&state, &grant, true, &correlation_id.0).await);
    }

    Ok(render_consent(&domain_id, &client_id, &grant))
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
async fn finish_decision(
    state: &ServiceState,
    grant: &DeviceCodeGrant,
    granted: bool,
    correlation_id: &str,
) -> Response {
    let client_id = client_id_for_display(state, &grant.client_id).await;
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
                build_initiator_unknown(),
                &grant.client_id,
                if granted { "success" } else { "failure" },
                (!granted).then(|| "consent denied".to_string()),
            );
            render_result(granted, &client_id)
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 device code grant decision update failed");
            error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}
