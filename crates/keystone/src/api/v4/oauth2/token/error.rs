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
//! RFC 6749 §5.2 token endpoint error response.

use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// RFC 6749 §5.2 token endpoint error response.
#[derive(Debug, Serialize)]
pub(crate) struct Oauth2TokenError {
    #[serde(skip)]
    status: StatusCode,
    #[serde(skip)]
    retry_after: Option<u64>,
    error: &'static str,
    error_description: String,
}

impl Oauth2TokenError {
    pub(crate) fn new(
        status: StatusCode,
        error: &'static str,
        description: impl Into<String>,
    ) -> Self {
        Self {
            status,
            retry_after: None,
            error,
            error_description: description.into(),
        }
    }

    pub(crate) fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub(crate) fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    pub(crate) fn unauthorized_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unauthorized_client", description)
    }

    pub(crate) fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            description,
        )
    }

    pub(crate) fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    pub(crate) fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }

    /// RFC 8628 §3.5: the device grant is still awaiting the user to
    /// complete the verification page.
    pub(crate) fn authorization_pending() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "the device grant is still pending user verification",
        )
    }

    /// RFC 8628 §3.5: the device polled more frequently than `interval`
    /// allows; it must back off.
    pub(crate) fn slow_down() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "slow_down",
            "polling too frequently; increase the interval",
        )
    }

    /// RFC 8628 §3.5: the user denied the device grant.
    pub(crate) fn access_denied() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "the user denied the device grant",
        )
    }

    /// RFC 8628 §3.5: the `device_code` has expired.
    pub(crate) fn expired_token() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "the device_code has expired; restart the device authorization flow",
        )
    }

    pub(crate) fn too_many_requests(retry_after: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            retry_after: Some(retry_after),
            // RFC 6749 §5.2 predates 429 and has no dedicated error code for
            // rate limiting; `invalid_request` is the closest defined code
            // (malformed/unacceptable request). The `429` status + `Retry-After`
            // header are the authoritative signal for clients.
            error: "invalid_request",
            error_description: "rate limit exceeded".to_string(),
        }
    }

    pub(crate) fn internal(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_request",
            description,
        )
    }
}

impl IntoResponse for Oauth2TokenError {
    fn into_response(self) -> Response {
        let status = self.status;
        let retry_after = self.retry_after;
        let mut response = (status, Json(self)).into_response();
        if let Some(retry_after) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, retry_after.into());
        }
        response
    }
}
