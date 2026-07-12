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
//! Dynamic auth plugin administration API (ADR 0025 §4): admin-authorized
//! external identity linking
//! (`/auth_plugins/{plugin_name}/identity_links`) and bulk `revoke_all`
//! (`/auth_plugins/{plugin_name}/revoke_all`, "Bulk Revocation on Plugin
//! Compromise").

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod identity_link;
mod revoke_all;

/// OpenApi specification for the auth-plugin admin API.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    identity_link::create::create,
    identity_link::delete::delete,
    revoke_all::revoke_all
))]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(identity_link::create::create))
        .routes(routes!(identity_link::delete::delete))
        .routes(routes!(revoke_all::revoke_all))
}
