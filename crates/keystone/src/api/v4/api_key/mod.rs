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
//! API Key (SCIM ingress machine identity) admin API (ADR 0021 §5).
//!
//! OPA input structure for all api_key operations:
//! ```text
//! {
//!   "credentials": { ... },
//!   "target": { "api_key": <object-or-null> },
//!   "existing": { "api_key": <object-or-null> }
//! }
//! ```
//!
//! | Operation       | `input.target.api_key`  | `input.existing.api_key` |
//! |------------------|--------------------------|---------------------------|
//! | Create           | ApiKeyCreate payload     | null                      |
//! | List             | ApiKeyListParameters     | null                      |
//! | Show             | null                     | current key               |
//! | Update           | ApiKeyUpdate patch       | current key               |
//! | Revoke           | null                     | current key               |
//! | SimulateAccess   | null                     | current key               |

use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

mod create;
mod list;
mod revoke;
mod show;
mod simulate_access;
mod update;

use crate::keystone::ServiceState;

/// OpenApi specification for the API Key (SCIM ingress) admin API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="api_key", description=r#"API Key (SCIM ingress) admin API (ADR 0021).

Stateless, domain-owned machine-identity credentials for M2M SCIM provisioning
ingress. Management of these credentials requires the `manager` role
(DomainManager) scoped to the key's own domain, or `admin` (SystemAdmin).
        "#),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(simulate_access::simulate_access))
        .routes(routes!(show::show, update::update))
        .routes(routes!(revoke::revoke))
}
