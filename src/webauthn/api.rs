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
//! # WebAuthN extension REST API

use axum::Router;
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use webauthn_rs::{WebauthnBuilder, prelude::Url};

use crate::error::KeystoneError;
use crate::keystone::ServiceState;

mod auth;
mod register;
mod types;

use crate::webauthn::driver::SqlDriver;
use types::{CombinedExtensionState, ExtensionState};

/// OpenApi specification for the user passkey support.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="passkey", description=r#"Passkey API."#),
    )
)]
pub struct ApiDoc;

/// OpenAPI router.
pub fn openapi_router() -> OpenApiRouter<CombinedExtensionState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/auth/passkey", auth::openapi_router())
        .nest("/users/{user_id}/passkeys", register::openapi_router())
}

/// Initialize the extension.
pub fn init_extension(main_state: ServiceState) -> Result<Router, KeystoneError> {
    // Effective domain name.
    let rp_id = "localhost";
    // Url containing the effective domain name
    // TODO: This must come from the configuration file.
    // MUST include the port number!
    let rp_origin = Url::parse("http://localhost:8080")?;
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;

    // Now, with the builder you can define other options.
    // Set a "nice" relying party name. Has no security properties and
    // may be changed in the future.
    let builder = builder.rp_name("Keystone");

    // Consume the builder and create our webauthn instance.
    let webauthn = builder.build()?;

    let extension_state = Arc::new(ExtensionState {
        provider: SqlDriver::default(),
        webauthn,
    });

    let combined_state = CombinedExtensionState {
        core: main_state,
        extension: extension_state,
    };
    let (router, _openapi) = OpenApiRouter::new()
        .merge(openapi_router())
        .with_state(combined_state)
        .split_for_parts();
    Ok(router)
}
