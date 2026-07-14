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
//! OAuth2/OIDC provider public API (ADR 0026).
//!
//! Phase 1 scope only: per-domain signing key publication. Unlike every
//! other v4 resource, these routes carry no `Auth` extractor and no policy
//! check — the JWKS endpoint must be reachable by relying parties and edge
//! proxies without a Keystone token (ADR 0026 §3).

use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

mod jwks;

use crate::keystone::ServiceState;

/// OpenApi specification for the OAuth2/OIDC provider public API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "oauth2", description = "OAuth2/OIDC provider public API (ADR 0026). Unauthenticated by design."),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(jwks::jwks))
}
