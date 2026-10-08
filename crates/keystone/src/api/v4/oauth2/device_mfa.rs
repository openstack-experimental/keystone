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
//! `POST /v4/oauth2/{domain_id}/device/mfa`: second-factor step of the
//! device verification page (see [`super::mfa`]).

use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum_extra::extract::CookieJar;
use cadf::{Outcome, OutcomeReason};
use serde::Deserialize;

use openstack_keystone_core::auth::ExecutionContext;

use super::device::{
    DEVICE_COOKIE_NAME, after_device_authentication, render_mfa, verify_csrf_token,
};
use super::html::{client_view, error_page, too_many_requests};
use super::mfa::{FACTOR_TOTP, TotpOutcome, amr_for, verify_totp};
use crate::api::common::PeerAddr;
use crate::audit::{
    CorrelationId, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_session_event,
};
use crate::keystone::ServiceState;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct DeviceMfaForm {
    csrf_token: String,
    factor: String,
    passcode: String,
}

/// `POST /v4/oauth2/{domain_id}/device/mfa`.
#[utoipa::path(
    post,
    path = "/{domain_id}/device/mfa",
    operation_id = "/oauth2:device_mfa",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "MFA form re-rendered after a wrong code, or the consent page", content_type = "text/html"),
        (status = BAD_REQUEST, description = "Missing/expired code, no second factor pending, or invalid CSRF token"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::device_mfa",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn device_mfa(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Form(form): Form<DeviceMfaForm>,
) -> Result<Response, std::convert::Infallible> {
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
    let sessions = state.provider.get_oauth2_session_provider();
    let grant = match sessions.get_device_code_grant(&state, &device_code).await {
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
    let Some(user_id) = grant.pending_user_id.clone() else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "no second factor pending; please restart",
        ));
    };
    if grant.user_id.is_some()
        || form.factor != FACTOR_TOTP
        || !grant.pending_factors.iter().any(|f| f == &form.factor)
    {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "no second factor pending; please restart",
        ));
    }

    let max_attempts = state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .mfa_max_attempts;
    if grant.mfa_attempts >= max_attempts {
        // Deny the grant so the polling device sees `access_denied` instead
        // of waiting for the code to expire.
        let _ = sessions
            .mark_device_decision(&state, &device_code, false)
            .await;
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "too many attempts; please restart",
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
                build_initiator_unknown(),
                &grant.client_id,
                Outcome::Failure,
                Some(OutcomeReason::literal("InvalidSecondFactor")),
            );
            let updated = match sessions
                .record_device_mfa_failure(&state, &device_code)
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
            if updated.mfa_attempts >= max_attempts {
                let _ = sessions
                    .mark_device_decision(&state, &device_code, false)
                    .await;
                return Ok(error_page(
                    StatusCode::BAD_REQUEST,
                    "too many attempts; please restart",
                ));
            }
            let client = client_view(&state, &updated.client_id).await;
            return Ok(render_mfa(
                &domain_id,
                &client,
                &updated,
                Some("invalid verification code"),
            ));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let grant = match sessions
        .mark_device_authenticated(
            &state,
            &device_code,
            &user_id,
            now,
            amr_for(&grant.pending_factors),
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

    let exec = ExecutionContext::internal(&state);
    let client = client_view(&state, &grant.client_id).await;
    Ok(after_device_authentication(
        &state,
        &exec,
        &domain_id,
        &client,
        &grant,
        &correlation_id.0,
    )
    .await)
}
