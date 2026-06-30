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
//! User API.
//!
//! OPA input structure for all user operations:
//! ```text
//! {
//!   "credentials": { ... },
//!   "target": { "user": <object-or-null> },
//!   "existing": { "user": <object-or-null> }
//! }
//! ```
//!
//! | Operation | `input.target.user`  | `input.existing.user` |
//! |-----------|-----------------------|------------------------|
//! | Create    | UserCreate payload    | null                   |
//! | Update    | UserUpdate patch      | current user           |
//! | Show      | null                  | current user           |
//! | Delete    | null                  | current user           |
//! | List      | UserListParameters    | null                   |

use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

pub mod types;

mod create;
mod delete;
mod groups;
mod list;
mod show;
mod update;

/// OpenApi specification for the user api.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="users", description=r#"User API.

User management endpoints for creating, retrieving, updating, and deleting users.
        "#),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, delete::remove))
        .routes(routes!(update::update))
        .routes(routes!(groups::groups))
}
