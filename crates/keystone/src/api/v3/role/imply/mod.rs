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

//! Role imply rules API.

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod check;
mod create;
mod delete;
mod get;
mod list;

/// OpenAPI router for role imply rules.
///
/// Routes:
/// - `HEAD /roles/{prior_role_id}/implies/{implied_role_id}` - check if imply
///   rule exists
/// - `GET /roles/{prior_role_id}/implies/{implied_role_id}` - get imply rule
///   details
/// - `PUT /roles/{prior_role_id}/implies/{implied_role_id}` - create imply rule
/// - `DELETE /roles/{prior_role_id}/implies/{implied_role_id}` - delete imply
///   rule
/// - `GET /roles/{prior_role_id}/implies` - list imply rules for a prior role
pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list))
        .routes(routes!(check::check))
        .routes(routes!(create::create))
        .routes(routes!(delete::delete))
        .routes(routes!(get::get))
}
