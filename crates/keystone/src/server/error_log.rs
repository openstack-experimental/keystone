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
//! # Error response body logging middleware
//!
//! `KeystoneApiError::into_response` logs its own diagnostic fields (see
//! `error_conv.rs`), but that only covers responses produced by handler code
//! that actually returns a `KeystoneApiError`. Extractor rejections (e.g.
//! `Query<T>`/`Json<T>`/`Path<T>` failing to deserialize) never reach the
//! handler and build their own response directly, bypassing that log
//! entirely — the body (which carries the only diagnostic detail, e.g. which
//! field failed to parse and why) was otherwise visible only to the client.
//!
//! This middleware logs the response body for any 4xx/5xx response,
//! regardless of where in the stack it was produced. Must be layered before
//! the compression layer (outside it, i.e. closer to the handler) so it
//! reads the body while it's still plain JSON.

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// Cap on how much of an error body we buffer for logging. Error bodies in
/// this codebase are small, hand-built JSON objects; a generous cap avoids
/// ever truncating a real one while still bounding memory use against a
/// pathological body.
const MAX_LOGGED_BODY_BYTES: usize = 64 * 1024;

pub async fn log_error_body(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }

    let (parts, body) = response.into_parts();
    match to_bytes(body, MAX_LOGGED_BODY_BYTES).await {
        Ok(bytes) => {
            // 5xx must be visible under a default INFO deployment; 4xx are
            // client-caused and stay at debug.
            if status.is_server_error() {
                tracing::error!(
                    status_code = status.as_u16(),
                    body = %String::from_utf8_lossy(&bytes),
                    "Returning error response",
                );
            } else {
                tracing::debug!(
                    status_code = status.as_u16(),
                    body = %String::from_utf8_lossy(&bytes),
                    "Returning error response",
                );
            }
            Response::from_parts(parts, Body::from(bytes))
        }
        Err(error) => {
            // Body couldn't be fully buffered (e.g. exceeded the cap above).
            // The stream is already partially consumed at this point, so
            // the original body can't be forwarded intact; log what we can
            // and fail closed with an empty body rather than send a
            // truncated/corrupt one.
            if status.is_server_error() {
                tracing::error!(
                    status_code = status.as_u16(),
                    %error,
                    "Failed to buffer error response body for logging",
                );
            } else {
                tracing::debug!(
                    status_code = status.as_u16(),
                    %error,
                    "Failed to buffer error response body for logging",
                );
            }
            Response::from_parts(parts, Body::empty())
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt as _;

    use super::*;

    async fn ok_handler() -> &'static str {
        "fine"
    }

    async fn err_handler() -> Response {
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(r#"{"error":{"message":"bad"}}"#))
            .expect("valid response")
    }

    #[tokio::test]
    async fn passes_through_success_body_unchanged() {
        let app = Router::new()
            .route("/ok", get(ok_handler))
            .layer(axum::middleware::from_fn(log_error_body));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        assert_eq!(&body[..], b"fine");
    }

    #[tokio::test]
    async fn preserves_error_body_after_logging() {
        let app = Router::new()
            .route("/err", get(err_handler))
            .layer(axum::middleware::from_fn(log_error_body));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/err")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        assert_eq!(&body[..], br#"{"error":{"message":"bad"}}"#);
    }
}
