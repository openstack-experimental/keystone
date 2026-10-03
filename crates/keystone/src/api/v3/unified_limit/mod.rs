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
//! # Unified limits API
//!
//! Keystone's "Unified Limits": `/v3/limits` -- the resource limits of
//! the projects and domains (plus the `/v3/limits/model` enforcement model
//! discovery) and `/v3/registered_limits` -- the service wide defaults of the
//! resource limits.

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

pub mod limit;
pub mod registered_limit;

/// OpenApi specification for the unified limits API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="limits", description=r#"In OpenStack, a quota system mainly contains two parts: `limit` and `usage`. The Unified limits in Keystone is a replacement of the `limit` part. It contains two kinds of resources: `Registered Limit` and `Limit`. A `registered limit` is a default limit. It is usually created by the services which are registered in Keystone. A `limit` is the limit that override the registered limit for each project."#)
    )
)]
pub struct ApiDoc;

pub(crate) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/limits", limit::openapi_router())
        .nest("/registered_limits", registered_limit::openapi_router())
}
