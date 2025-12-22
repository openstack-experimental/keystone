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
//! # Keystone API
//!
//! Keystone is following the API first principles. The user or other services
//! interact with it using the API.
use axum::{
    extract::State,
    http::{HeaderMap, header},
    response::IntoResponse,
};
use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
};
use utoipa_axum::{router::OpenApiRouter, routes};

pub use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

pub mod auth;
pub(crate) mod common;
pub mod error;
pub mod types;
pub mod v3;
pub mod v4;

use crate::api::types::*;

/// OpenApi specification.
#[derive(OpenApi)]
#[openapi(
    info(version = "4.0.1"),
    modifiers(&SecurityAddon),
    nest(
      (path = "v3", api = v3::ApiDoc),
      (path = "v4", api = v4::ApiDoc),
    ),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "x-auth",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("x-auth-token"))),
            );
        }
    }
}

/// Main API router.
pub fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/v3", v3::openapi_router())
        .nest("/v4", v4::openapi_router())
        .routes(routes!(version))
}

/// Version discovery endpoint.
#[utoipa::path(
    get,
    path = "/",
    description = "Version discovery",
    responses(
        (status = OK, description = "Versions", body = Versions),
    ),
    tag = "version"
)]
async fn version(
    headers: HeaderMap,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let host = state
        .config
        .default
        .public_endpoint
        .clone()
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|header| header.to_str().map(|val| format!("http://{val}")).ok())
        })
        .unwrap_or_else(|| "http://localhost".to_string());

    let res = Versions {
        versions: Values {
            values: vec![
                Version {
                    id: "v3.14".into(),
                    status: VersionStatus::Stable,
                    links: Some(vec![Link::new(format!("{host}/v3"))]),
                    media_types: Some(vec![MediaType::default()]),
                    ..Default::default()
                },
                Version {
                    id: "v4.0".into(),
                    status: VersionStatus::Experimental,
                    links: Some(vec![Link::new(format!("{host}/v4"))]),
                    media_types: Some(vec![MediaType::default()]),
                    ..Default::default()
                },
            ],
        },
    };
    Ok(res)
}
