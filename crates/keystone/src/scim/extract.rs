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
//! [`ScimJson`]: a body extractor that converts a malformed-JSON rejection
//! into a SCIM-shaped `ScimErrorBody` (`scimType: "invalidSyntax"`, RFC
//! 7644 §3.12) instead of Axum's default `Json<T>` rejection body. The
//! content-type negotiation middleware (`scim::content_type`) already
//! rejects an unsupported/missing `Content-Type` before a handler runs, so
//! any rejection reaching this extractor is a genuinely malformed body on
//! an otherwise-accepted content type.

use axum::{
    Json,
    extract::{FromRequest, Request, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;

use crate::scim::error::{SCIM_ERROR_SCHEMA, ScimErrorBody};

pub struct ScimJson<T>(pub T);

impl<S, T> FromRequest<S> for ScimJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(invalid_syntax(&rejection)),
        }
    }
}

fn invalid_syntax(rejection: &JsonRejection) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ScimErrorBody {
            schemas: vec![SCIM_ERROR_SCHEMA.to_string()],
            status: StatusCode::BAD_REQUEST.as_str().to_string(),
            scim_type: Some("invalidSyntax".to_string()),
            detail: rejection.to_string(),
        }),
    )
        .into_response()
}
