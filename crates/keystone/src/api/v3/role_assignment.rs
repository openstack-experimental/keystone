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

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

pub mod types;

mod domain;
mod list;
mod project;
mod system;

/// Policy target for an object that may not exist.
///
/// Policy is evaluated before a missing group/user/role is reported as 404,
/// so that unauthorized callers cannot probe for the existence of ids.
pub(crate) fn policy_target<T: serde::Serialize>(obj: &Option<T>, id: &str) -> serde_json::Value {
    obj.as_ref()
        .and_then(|x| serde_json::to_value(x).ok())
        .unwrap_or_else(|| serde_json::json!({"id": id}))
}

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list))
        .merge(domain::openapi_router())
        .merge(project::openapi_router())
        .merge(system::openapi_router())
}
