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
//! SCIM realm CRUD (ADR 0024 §2.A). Registering a realm is an explicit
//! administrative act, separate from creating an `ApiClientResource` (ADR
//! 0021): the latter authenticates, this authorizes SCIM Users/Groups
//! resource provisioning for the same `(domain_id, provider_id)`
//! coordinate.

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::keystone::ServiceState;

mod create;
mod list;
mod purge;
mod show;
mod update;

#[derive(OpenApi)]
#[openapi(tags((name="scim_realm", description=r#"
SCIM realm administration. A SCIM realm is the explicit administrative
activation of an `(domain_id, provider_id)` coordinate for SCIM Users/Groups
resource provisioning (ADR 0024).
"#)))]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, update::update))
        .routes(routes!(purge::purge))
}
