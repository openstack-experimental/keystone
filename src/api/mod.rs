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
//! Keystone API
use axum::{
    extract::State,
    http::{HeaderMap, header},
    response::IntoResponse,
};
use utoipa::{
    Modify, OpenApi,
    openapi::security::{
        ApiKey, ApiKeyValue, AuthorizationCode, Flow, HttpAuthScheme, HttpBuilder, OAuth2, Scopes,
        SecurityScheme,
    },
};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

pub mod auth;
pub(crate) mod common;
pub mod error;
pub mod types;
pub mod v3;
pub mod v4;

use crate::api::types::*;

#[derive(OpenApi)]
#[openapi(
    info(version = "4.0.1"),
    modifiers(&SecurityAddon),
    tags(
        (name="identity_providers", description=v4::federation::identity_provider::DESCRIPTION),
        (name="mappings", description=v4::federation::mapping::DESCRIPTION),
        (name="token", description=v4::token::DESCRIPTION),
        (name="token_restrictions", description=v4::token::restriction::DESCRIPTION),
    )
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
            components.add_security_scheme(
                "jwt",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("JWT (ID) Token issued by the federated IDP"))
                        .build(),
                ),
            );
            // TODO: This must be dynamic
            components.add_security_scheme(
                "oauth2",
                SecurityScheme::OAuth2(OAuth2::new([Flow::AuthorizationCode(
                    AuthorizationCode::new(
                        "https://localhost/authorization/token",
                        "https://localhost/token/url",
                        Scopes::from_iter([("openid", "default scope")]),
                    ),
                )])),
            );
        }
    }
}

pub fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/v3", v3::openapi_router())
        .nest("/v4", v4::openapi_router())
        .routes(routes!(version))
}

/// Versions
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
        .as_ref()
        .and_then(|dflt| dflt.public_endpoint.clone())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|header| header.to_str().map(|val| format!("http://{val}")).ok())
            //.and_then(|header| format!("http://{}", header.to_str().ok()).into())
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
