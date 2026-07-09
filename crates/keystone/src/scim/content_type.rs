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
//! Content-type negotiation middleware (RFC 7644 §3.1): every bodied
//! `/SCIM/v2` request must declare `application/scim+json` or (for
//! backwards-compatible clients) plain `application/json`; anything else is
//! rejected with `415` before it reaches a handler. Every response leaving
//! the sub-router has its `Content-Type` normalized to
//! `application/scim+json`, so individual handlers don't each need to set
//! it.

use axum::{
    Json,
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::error::{SCIM_ERROR_SCHEMA, ScimErrorBody};

const SCIM_CONTENT_TYPE: &str = "application/scim+json";

fn unsupported_media_type(detail: &str) -> Response {
    (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Json(ScimErrorBody {
            schemas: vec![SCIM_ERROR_SCHEMA.to_string()],
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE.as_str().to_string(),
            scim_type: None,
            detail: detail.to_string(),
        }),
    )
        .into_response()
}

/// Whether the request carries a body, per `Content-Length` (or chunked
/// `Transfer-Encoding`) -- checked instead of buffering the body so a
/// bodiless probe (e.g. a client testing whether a method is supported at
/// all) doesn't get short-circuited with `415` before Axum's own
/// unmapped-method `405` dispatch ever runs.
fn has_body(req: &Request) -> bool {
    let has_content_length = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > 0);
    has_content_length || req.headers().contains_key(header::TRANSFER_ENCODING)
}

pub async fn enforce_scim_content_type(req: Request, next: Next) -> Response {
    let expects_body =
        matches!(req.method(), &Method::POST | &Method::PUT | &Method::PATCH) && has_body(&req);

    if expects_body {
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or(v).trim().to_ascii_lowercase());

        match content_type.as_deref() {
            Some(SCIM_CONTENT_TYPE) | Some("application/json") => {}
            _ => {
                return unsupported_media_type(
                    "Content-Type must be application/scim+json or application/json",
                );
            }
        }
    }

    let mut response = next.run(req).await;

    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        == Some("application/json")
    {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(SCIM_CONTENT_TYPE),
        );
    }

    response
}
