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

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

pub mod restriction;
pub mod types;

/// OpenApi specification for the token api.
#[derive(OpenApi)]
#[openapi(
    nest(
        (path = "token_restrictions", api = restriction::ApiDoc),
    ),
    tags(
        (name = "token", description = r#"Token API"#),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().nest("/restrictions", restriction::openapi_router())
}
