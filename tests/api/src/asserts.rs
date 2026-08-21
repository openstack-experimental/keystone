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
//! Negative-test assertion helpers (issue #992 deliverable 2).
//!
//! Every helper funnels through [`status_from_error`], which extracts the
//! HTTP status code from the error chain of an [`eyre::Report`] produced by
//! the `openstack_sdk` request machinery. Assertion failures always report
//! the expected status, the extracted status, and the complete original
//! error chain.

use std::future::Future;

use eyre::{Report, Result};
use http::StatusCode;
use openstack_sdk::{OpenStackError, RestError, api::ApiError};
use reqwest::Response;

use crate::common::raw_request;

/// A raw request expected to be rejected as unauthenticated.
#[derive(Debug)]
pub struct RawUnauthorizedRequest<'a> {
    pub method: http::Method,
    pub path: &'a str,
    pub body: Option<serde_json::Value>,
    pub message: &'a str,
}

/// Assert the status carried by a raw HTTP response.
#[track_caller]
pub fn assert_response_status(response: &Response, expected: StatusCode, message: &str) {
    let actual = response.status();
    assert!(
        actual == expected,
        "{message}: expected HTTP {expected}, got {actual}; URL: {}",
        response.url()
    );
}

/// Send one raw request and assert a 401 response.
pub async fn assert_raw_request_unauthorized(
    request: RawUnauthorizedRequest<'_>,
    token: Option<&str>,
) -> Result<()> {
    assert_raw_request_unauthorized_with_cleanup(request, token, |_| async { Ok(()) }).await
}

/// Send one raw request and assert a 401 response, cleaning up any resource
/// created if a regression unexpectedly allows the request.
pub async fn assert_raw_request_unauthorized_with_cleanup<F, CleanupFuture>(
    request: RawUnauthorizedRequest<'_>,
    token: Option<&str>,
    cleanup: F,
) -> Result<()>
where
    F: FnOnce(Response) -> CleanupFuture,
    CleanupFuture: Future<Output = Result<()>>,
{
    let response = raw_request(request.method, request.path, token, request.body).await?;
    let response = if response.status().is_success() {
        cleanup(response).await?;
        panic!("{}: request unexpectedly succeeded", request.message);
    } else {
        response
    };
    assert_unauthorized(response.error_for_status().map(|_| ()), request.message);
    Ok(())
}

/// Assert the same authentication mode across a request matrix.
pub async fn assert_raw_requests_unauthorized<'a>(
    requests: impl IntoIterator<Item = RawUnauthorizedRequest<'a>>,
    token: Option<&str>,
) -> Result<()> {
    for request in requests {
        assert_raw_request_unauthorized(request, token).await?;
    }
    Ok(())
}

/// Extract the HTTP status code carried by an error chain, if any.
///
/// Walks the [`Report`] chain and inspects every cause for the
/// status-bearing `openstack_sdk` error shapes:
///
/// - [`ApiError::OpenStack`], [`ApiError::OpenStackService`],
///   [`ApiError::OpenStackUnrecognized`] (direct API errors),
/// - [`OpenStackError::Api`] (session-level wrapper around an [`ApiError`]),
/// - [`OpenStackError::Http`] (auth/session HTTP errors).
/// - [`reqwest::Error`] (raw HTTP helpers after `error_for_status`).
///
/// Both enums are `#[non_exhaustive]`; any variant that does not carry an
/// HTTP status — including variants added by future SDK versions — yields
/// `None`.
pub fn status_from_error(report: &Report) -> Option<StatusCode> {
    for cause in report.chain() {
        if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>()
            && let Some(status) = reqwest_err.status()
        {
            return Some(status);
        }
        if let Some(api_err) = cause.downcast_ref::<ApiError<RestError>>()
            && let Some(status) = status_from_api_error(api_err)
        {
            return Some(status);
        }
        if let Some(os_err) = cause.downcast_ref::<OpenStackError>() {
            match os_err {
                OpenStackError::Http { status } => return Some(*status),
                OpenStackError::Api { source } => {
                    if let Some(status) = status_from_api_error(source) {
                        return Some(status);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn status_from_api_error(err: &ApiError<RestError>) -> Option<StatusCode> {
    match err {
        ApiError::OpenStack { status, .. }
        | ApiError::OpenStackService { status, .. }
        | ApiError::OpenStackUnrecognized { status, .. } => Some(*status),
        _ => None,
    }
}

/// Assert that `result` failed with the given HTTP status.
///
/// Panics with `msg`, the expected status, the extracted status and the
/// complete error chain when the result is `Ok` or carries a different (or
/// no) status.
#[track_caller]
pub fn assert_status<T, E>(result: Result<T, E>, expected: StatusCode, msg: &str)
where
    T: std::fmt::Debug,
    E: Into<Report>,
{
    match result {
        Ok(value) => {
            panic!("{msg}: expected HTTP {expected}, but the request succeeded with: {value:#?}")
        }
        Err(err) => {
            let report: Report = err.into();
            let actual = status_from_error(&report);
            if actual != Some(expected) {
                panic!("{msg}: expected HTTP {expected}, got {actual:?}; error chain: {report:?}");
            }
        }
    }
}

/// Assert that `result` failed with HTTP 403 Forbidden (policy denial).
#[track_caller]
pub fn assert_forbidden<T, E>(result: Result<T, E>, msg: &str)
where
    T: std::fmt::Debug,
    E: Into<Report>,
{
    assert_status(result, StatusCode::FORBIDDEN, msg);
}

/// Assert that `result` failed with HTTP 401 Unauthorized (invalid auth).
#[track_caller]
pub fn assert_unauthorized<T, E>(result: Result<T, E>, msg: &str)
where
    T: std::fmt::Debug,
    E: Into<Report>,
{
    assert_status(result, StatusCode::UNAUTHORIZED, msg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::eyre;
    use http::Uri;

    fn forbidden_api_error() -> ApiError<RestError> {
        ApiError::OpenStack {
            status: StatusCode::FORBIDDEN,
            uri: Uri::from_static("http://localhost/v3/groups"),
            msg: "policy denied".into(),
            req_id: Some("req-1".into()),
        }
    }

    #[test]
    fn extracts_status_from_direct_openstack_variant() {
        let report = Report::new(forbidden_api_error());
        assert_eq!(status_from_error(&report), Some(StatusCode::FORBIDDEN));
    }

    #[test]
    fn extracts_status_from_openstack_service_variant() {
        let report = Report::new(ApiError::<RestError>::OpenStackService {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            uri: Uri::from_static("/"),
            data: "boom".into(),
            req_id: None,
        });
        assert_eq!(
            status_from_error(&report),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
    }

    #[test]
    fn extracts_status_from_openstack_unrecognized_variant() {
        let report = Report::new(ApiError::<RestError>::OpenStackUnrecognized {
            status: StatusCode::UNAUTHORIZED,
            uri: Uri::from_static("/"),
            obj: serde_json::json!({"weird": true}),
            req_id: None,
        });
        assert_eq!(status_from_error(&report), Some(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn extracts_status_from_wrapped_openstack_error_api() {
        let report = Report::new(OpenStackError::Api {
            source: forbidden_api_error(),
        });
        assert_eq!(status_from_error(&report), Some(StatusCode::FORBIDDEN));
    }

    #[test]
    fn extracts_status_from_openstack_error_http() {
        let report = Report::new(OpenStackError::Http {
            status: StatusCode::UNAUTHORIZED,
        });
        assert_eq!(status_from_error(&report), Some(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn extracts_status_through_context_wrapping() {
        let report = Report::new(forbidden_api_error()).wrap_err("creating group failed");
        assert_eq!(status_from_error(&report), Some(StatusCode::FORBIDDEN));
    }

    #[test]
    fn returns_none_for_error_without_status() {
        let report = eyre!("some non-HTTP failure");
        assert_eq!(status_from_error(&report), None);
    }

    #[test]
    fn returns_none_for_statusless_api_error_variant() {
        let report = Report::new(ApiError::<RestError>::ResourceNotFound);
        assert_eq!(status_from_error(&report), None);
    }

    #[test]
    fn assert_forbidden_accepts_403() {
        let result: Result<(), Report> = Err(Report::new(forbidden_api_error()));
        assert_forbidden(result, "must accept 403");
    }

    #[test]
    fn assert_forbidden_accepts_reqwest_error() -> eyre::Result<()> {
        let response = reqwest::Response::from(
            http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body("")?,
        );
        assert_forbidden(response.error_for_status(), "must accept raw HTTP 403");
        Ok(())
    }

    #[test]
    #[should_panic(expected = "expected HTTP 403")]
    fn assert_forbidden_panics_on_success() {
        let result: Result<(), Report> = Ok(());
        assert_forbidden(result, "must reject Ok");
    }

    #[test]
    #[should_panic(expected = "error chain")]
    fn assert_forbidden_panics_on_wrong_status_with_chain() {
        let result: Result<(), Report> = Err(Report::new(OpenStackError::Http {
            status: StatusCode::UNAUTHORIZED,
        }));
        assert_forbidden(result, "401 is not 403");
    }

    #[test]
    fn assert_unauthorized_accepts_401() {
        let result: Result<(), Report> = Err(Report::new(OpenStackError::Http {
            status: StatusCode::UNAUTHORIZED,
        }));
        assert_unauthorized(result, "must accept 401");
    }

    #[test]
    fn assert_status_accepts_concrete_error_types() {
        // `E: Into<Report>` must accept a bare SDK error, not only Report.
        let result: Result<(), ApiError<RestError>> = Err(forbidden_api_error());
        assert_status(result, StatusCode::FORBIDDEN, "bare ApiError");
    }
}
