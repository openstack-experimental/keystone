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
//! `POST /v4/oauth2/{domain_id}/authorize/mfa`: second-factor step of the
//! browser login (see [`super::mfa`]).

use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum_extra::extract::CookieJar;
use cadf::{Outcome, OutcomeReason};
use serde::Deserialize;

use super::authorize::{SESSION_COOKIE_NAME, after_authentication, render_mfa, verify_csrf_token};
use super::html::{client_view, error_page, fetch_client, too_many_requests};
use super::mfa::{FACTOR_TOTP, TotpOutcome, amr_for, verify_totp};
use crate::api::common::PeerAddr;
use crate::audit::{CorrelationId, build_initiator_from_user_id, emit_oauth2_session_event};
use crate::keystone::ServiceState;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct MfaForm {
    csrf_token: String,
    factor: String,
    passcode: String,
}

/// `POST /v4/oauth2/{domain_id}/authorize/mfa`.
#[utoipa::path(
    post,
    path = "/{domain_id}/authorize/mfa",
    operation_id = "/oauth2:authorize_mfa",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "MFA form re-rendered after a wrong code, or the consent page", content_type = "text/html"),
        (status = BAD_REQUEST, description = "Missing/expired session, no second factor pending, or invalid CSRF token"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::authorize_mfa",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn authorize_mfa(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Form(form): Form<MfaForm>,
) -> Result<Response, std::convert::Infallible> {
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
    let sessions = state.provider.get_oauth2_session_provider();
    let session = match sessions.get_pre_auth_session(&state, &session_id).await {
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
    let Some(user_id) = session.pending_user_id.clone() else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "no second factor pending; please restart sign-in",
        ));
    };
    if session.user_id.is_some()
        || form.factor != FACTOR_TOTP
        || !session.pending_factors.iter().any(|f| f == &form.factor)
    {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "no second factor pending; please restart sign-in",
        ));
    }

    let max_attempts = state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .mfa_max_attempts;
    // Count the attempt before checking the code so concurrent guesses
    // cannot all slip past the budget check.
    let attempted = match sessions.record_mfa_attempt(&state, &session_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 pre-auth session update failed");
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };
    if attempted.mfa_attempts > max_attempts {
        let _ = sessions
            .complete_pre_auth_session(&state, &session_id)
            .await;
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "too many attempts; please restart sign-in",
        ));
    }

    match verify_totp(&state, &user_id, form.passcode.trim()).await {
        TotpOutcome::Verified => {}
        TotpOutcome::RateLimited(retry_after) => return Ok(too_many_requests(retry_after)),
        TotpOutcome::Failed => {
            return Ok(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
        TotpOutcome::Invalid => {
            emit_oauth2_session_event(
                &state.audit_dispatcher,
                &correlation_id.0,
                "authenticate",
                build_initiator_from_user_id(&user_id, &session.domain_id),
                &session.client_id,
                Outcome::Failure,
                Some(OutcomeReason::literal("InvalidSecondFactor")),
            );
            if attempted.mfa_attempts >= max_attempts {
                let _ = sessions
                    .complete_pre_auth_session(&state, &session_id)
                    .await;
                return Ok(error_page(
                    StatusCode::BAD_REQUEST,
                    "too many attempts; please restart sign-in",
                ));
            }
            let client_ui = client_view(&state, &attempted.client_id).await;
            return Ok(render_mfa(
                &domain_id,
                &attempted,
                &client_ui,
                Some("invalid verification code"),
            ));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let session = match sessions
        .mark_authenticated(
            &state,
            &session_id,
            &user_id,
            now,
            amr_for(&session.pending_factors),
        )
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

    let client = fetch_client(&state, &session.client_id).await;
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
