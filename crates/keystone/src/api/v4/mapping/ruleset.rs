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
//! Mapping ruleset API.
//!
//! OPA input structure for all mapping/ruleset operations:
//! ```text
//! {
//!   "credentials": { ... },
//!   "target": { "mapping": <object-or-null> },
//!   "existing": { "mapping": <object-or-null> }
//! }
//! ```
//!
//! | Operation | `input.target.mapping`       | `input.existing.mapping` |
//! |-----------|------------------------------|--------------------------|
//! | Create    | MappingRuleSetCreate payload | null                     |
//! | Update    | MappingRuleSetUpdate patch   | current ruleset          |
//! | Mutate    | RuleMutations payload        | current ruleset          |
//! | Show      | null                         | current ruleset          |
//! | Delete    | null                         | current ruleset          |
//! | List      | MappingRuleSetListParameters | null                     |

use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

mod create;
mod delete;
mod list;
mod mutate;
mod show;
mod update;

use crate::keystone::ServiceState;

/// OpenApi specification for the mapping ruleset api.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="mapping_ruleset", description=r#"Mapping ruleset API.

The unified mapping engine provides a centralized, protocol-blind rules engine for identity federation.
Rulesets map external claims to localized authorization contexts.
        "#),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(
            show::show,
            delete::remove,
            update::update,
            mutate::mutate
        ))
}
