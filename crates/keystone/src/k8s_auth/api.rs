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
//! # Kubernetes auth API
//!
//! - AuthInstance
//! - AuthRole
//! - Auth
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

pub mod auth;
//mod common;
pub mod error;
pub mod instance;
pub mod role;
pub mod types;

/// OpenApi specification for the K8s auth module.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="k8s_auth_instance", description=r#"Kubernetes authentication instances (Kubernetes Clusters) API.

Authentication Instance represents a remote Kubernetes cluster that issues the JWT token for the service account which could be exchanged for the Keystone token using the corresponding auth_role.
"#),
        (name="k8s_auth_role", description=r#"Kubernetes auth role API.

K8s auth roles define how the JWT token of the Kubernetes pod running as a service account should be mapped to the local user during the token exchange.
"#),
    )
)]
pub struct ApiDoc;

pub fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/instance", instance::openapi_router())
        .merge(role::openapi_router())
        .merge(auth::openapi_router())
}
