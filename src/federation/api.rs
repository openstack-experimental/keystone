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
//! # Federation API
//!
//! - IDP
//! - Mapping
//! - Auth initialization
//! - Auth callback
use utoipa::{
    Modify, OpenApi,
    openapi::security::{
        AuthorizationCode, Flow, HttpAuthScheme, HttpBuilder, OAuth2, Scopes, SecurityScheme,
    },
};
use utoipa_axum::router::OpenApiRouter;

use crate::keystone::ServiceState;

pub mod auth;
mod common;
pub mod error;
pub mod identity_provider;
pub mod jwt;
pub mod mapping;
pub mod oidc;
pub mod types;

/// OpenApi specification for the federation.
#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityFederationAddon),
    tags(
        (name="identity_providers", description=r#"Identity providers API.

Identity provider resource allows to federate users from an external Identity Provider (i.e.
Keycloak, Azure AD, etc.).

Using the Identity provider requires creation of the mapping, which describes how to map attributes
of the remote Idp to local users.

Identity provider with an empty domain_id are considered globals and every domain may use it with
appropriate mapping."#),
        (name="mappings", description=r#"Federation mappings API.

Mappings define how the user attributes on the remote IDP are mapped to the local user.

Mappings with an empty domain_id are considered globals and every domain may use it. Such mappings
require the `domain_id_claim` attribute to be set to identify the domain_id for the respective
user."#),
    )
)]
pub struct ApiDoc;

pub fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/identity_providers", identity_provider::openapi_router())
        .nest("/mappings", mapping::openapi_router())
        .merge(auth::openapi_router())
        .merge(jwt::openapi_router())
        .merge(oidc::openapi_router())
}

struct SecurityFederationAddon;
impl Modify for SecurityFederationAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
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
