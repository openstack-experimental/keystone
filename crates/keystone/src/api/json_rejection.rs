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
//! Normalizes Axum's built-in `Json<T>` extractor rejections.
//!
//! Every v3/v4 handler takes its request body as a plain `axum::Json<T>`
//! parameter. When the body fails to deserialize, Axum answers the request
//! itself -- the handler never runs, so `KeystoneApiError` (which already
//! has a `From<JsonRejection>` impl, `crates/api-types/src/error_conv.rs`)
//! never gets a chance to apply. Axum's own rejection response is
//! `text/plain`, and for a type-mismatch payload (e.g. a string where a
//! bool is expected) it answers `422 Unprocessable Entity` -- but python
//! keystone (and this codebase's own `KeystoneApiError::UnprocessableEntity`
//! convention, reserved for semantic write-time validation) answers `400
//! Bad Request` for a malformed body. Confirmed against tempest:
//! `EndpointsNegativeTestJSON.test_create_with_enabled_False` sends
//! `"enabled": "False"` (a string) and asserts a 400.
//!
//! This response-mapping middleware rewrites any `text/plain` response in
//! the `400/415/422` family coming out of the v3/v4 router into the
//! standard `{"error": {"code", "message"}}` JSON shape, remapping Axum's
//! `422` (`JsonDataError`) down to `400` to match. Nothing else in this
//! router ever answers `text/plain` (confirmed: only the `/metrics`
//! endpoint and an outbound test HTTP mock use that content type, and
//! neither is mounted under this router), so the content-type check alone
//! is a safe discriminator.

use axum::body::{Body, to_bytes};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

const MAX_BODY_BYTES: usize = 64 * 1024;

pub(crate) async fn normalize_json_rejection(response: Response) -> Response {
    let is_text_plain = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/plain"));

    let status = response.status();
    if !is_text_plain
        || !matches!(
            status,
            StatusCode::BAD_REQUEST
                | StatusCode::UNSUPPORTED_MEDIA_TYPE
                | StatusCode::UNPROCESSABLE_ENTITY
        )
    {
        return response;
    }

    let new_status = if status == StatusCode::UNPROCESSABLE_ENTITY {
        StatusCode::BAD_REQUEST
    } else {
        status
    };

    let (parts, body) = response.into_parts();
    let message = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => {
            return Response::from_parts(parts, Body::empty());
        }
    };

    (
        new_status,
        axum::Json(json!({"error": {"code": new_status.as_u16(), "message": message}})),
    )
        .into_response()
}
