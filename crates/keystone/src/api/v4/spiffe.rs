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
//! # SPIFFE api

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

pub mod binding;

/// OpenApi specification for the SPIFFE api.
#[derive(OpenApi)]
#[openapi(
    nest(
        (path = "bindings", api = binding::ApiDoc),
    ),
    tags(
        (name="spiffe", description=r#"SPIFFE integration API.

SPIFFE bindings can be used to map SVID to the OpenStack authorization (Actor/Scope/Roles).
        "#),
    )
)]
pub struct ApiDoc;
pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().nest("/bindings", binding::openapi_router())
}
