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
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
mod delete;
mod list;
mod show;
pub mod types;

/// OpenApi specification for the application-credential API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="application_credentials", 
        description=r#"Application Credentials are a way to authenticate to the OpenStack Identity service without using a user's password. They are useful for applications that need to interact with OpenStack services.
"#),
    )
)]
pub struct ApiDoc;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(create::create))
        .routes(routes!(delete::delete))
        .routes(routes!(list::list))
        .routes(routes!(show::show))
}
