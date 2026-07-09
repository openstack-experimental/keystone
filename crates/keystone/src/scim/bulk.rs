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
//! `POST /Bulk` (RFC 7644 §3.7) and `GET /Me` (RFC 7644 §3.11) -- both
//! explicitly out of scope for ADR 0024 (§5.F; `bulk.supported: false` in
//! `ServiceProviderConfig`, and there is no "current SCIM resource" concept
//! for an API-key-authenticated provisioning client). Rather than falling
//! through to Axum's default unmapped-route `404` (a non-SCIM-shaped body),
//! these return a clean `501` with a proper `ScimErrorBody` so RFC 7644
//! clients that probe these endpoints get a recognizable response.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::scim::error::{SCIM_ERROR_SCHEMA, ScimErrorBody};

fn not_implemented(detail: &str) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ScimErrorBody {
            schemas: vec![SCIM_ERROR_SCHEMA.to_string()],
            status: StatusCode::NOT_IMPLEMENTED.as_str().to_string(),
            scim_type: None,
            detail: detail.to_string(),
        }),
    )
        .into_response()
}

pub(super) async fn bulk() -> Response {
    not_implemented("bulk operations are not supported (see ServiceProviderConfig)")
}

pub(super) async fn me() -> Response {
    not_implemented("/Me is not supported for API-key-authenticated SCIM clients")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bulk_returns_501() {
        let rsp = bulk().await;
        assert_eq!(rsp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_me_returns_501() {
        let rsp = me().await;
        assert_eq!(rsp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
