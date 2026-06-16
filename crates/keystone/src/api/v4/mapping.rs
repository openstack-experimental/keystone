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
//! # Mapping API

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

pub mod ruleset;

/// OpenApi specification for the mapping API.
#[derive(OpenApi)]
#[openapi(
    nest(
        (path = "rulesets", api = ruleset::ApiDoc),
    ),
    tags(
        (name="mapping", description=r#"Mapping engine API.

The unified mapping engine provides a centralized, protocol-blind rules engine for identity federation.
Rulesets map external claims to localized authorization contexts.
        "#),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().nest("/rulesets", ruleset::openapi_router())
}
