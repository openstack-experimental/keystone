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
//! # OS-OAUTH2 API
//!
//! OAuth2.0 Client Credentials Grant Flow (RFC 6749 §4.4).

mod create;
pub mod types;

use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

/// OpenApi specification for the OS-OAUTH2 API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "OS-OAUTH2", description = "OAuth2.0 token endpoint. Supports the client credentials grant type (RFC 6749 §4.4) for issuing access tokens using application credentials."),
    )
)]
pub struct ApiDoc;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(create::create))
}
