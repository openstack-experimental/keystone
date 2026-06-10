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
//! # Project API

use crate::keystone::ServiceState;
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

mod create; // v4-specific create with optional id
mod types;

/// OpenApi specification for the v4 project API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="projects", description="Project API - v4 supports optional project_id"),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(create::create)) // v4-specific with optional id
        .merge(crate::api::v3::project::v3_handlers_router()) // reuse non-breaking v3 endpoints
}
