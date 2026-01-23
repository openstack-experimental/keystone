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

//! v3 API.

use axum::{
    extract::{OriginalUri, Request, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

pub mod auth;
pub mod group;
pub mod project;
pub mod role;
pub mod role_assignment;
pub mod user;

use crate::api::types::*;

/// OpenApi specification for v3.
#[derive(OpenApi)]
#[openapi(
    nest(
      (path = "/roles", api = role::ApiDoc),
    ),
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/auth", auth::openapi_router())
        .nest("/groups", group::openapi_router())
        .nest("/projects", project::openapi_router())
        .nest("/roles", role::openapi_router())
        .nest("/users", user::openapi_router())
        .merge(role_assignment::openapi_router())
        .routes(routes!(version))
}

/// Version discovery endpoint
#[utoipa::path(
    get,
    path = "/",
    description = "Version discovery",
    responses(
        (status = OK, description = "Versions", body = SingleVersion),
    ),
    tag = "version"
)]
async fn version(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    State(state): State<ServiceState>,
    _req: Request,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let host = state
        .config
        .default
        .public_endpoint
        .clone()
        .map(|x| x.to_string())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|header| header.to_str().map(|val| format!("http://{val}")).ok())
        })
        .unwrap_or_else(|| "http://localhost".to_string());
    let link = Link {
        rel: "self".into(),
        href: format!("{}{}", host, uri.path()),
    };
    let version = Version {
        id: "v3.14".into(),
        status: VersionStatus::Stable,
        links: Some(vec![link]),
        media_types: Some(vec![MediaType::default()]),
        ..Default::default()
    };
    let res = SingleVersion { version };
    Ok(res)
}
