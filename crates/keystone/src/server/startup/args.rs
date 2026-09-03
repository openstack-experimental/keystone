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

//! CLI argument definition and the `--dump-openapi` fast path.

use std::path::PathBuf;

use axum::Router;
use clap::{Parser, ValueEnum};
use color_eyre::eyre::{Report, Result};
use utoipa::OpenApi;

use crate::{api, webauthn};
use openstack_keystone_core::keystone::ServiceState;

/// `OpenStack` Keystone.
///
/// Keystone is an `OpenStack` service that provides API client authentication,
/// service discovery, and distributed multi-tenant authorization by
/// implementing OpenStack's Identity API.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Path to the keystone config file.
    #[arg(short, long, default_value = "/etc/keystone/keystone.conf")]
    pub config: PathBuf,

    /// Verbosity level. Repeat to increase level.
    #[arg(short, long, global=true, action = clap::ArgAction::Count, display_order = 920)]
    pub verbose: u8,

    /// Print the `OpenAPI` schema json instead of running the Keystone.
    #[arg(long)]
    pub dump_openapi: Option<OpenApiFormat>,
}

#[derive(Clone, Debug, Default, PartialEq, ValueEnum)]
pub enum OpenApiFormat {
    /// Json.
    Json,
    #[default]
    /// Yaml.
    Yaml,
}

/// Build the merged `OpenAPI` document and the main application router.
///
/// Returned as a pair because the router is needed by
/// [`super::router::build`] while the document is needed both here (for
/// `--dump-openapi`) and there (for the Swagger UI mount).
pub fn build_api() -> (Router<ServiceState>, utoipa::openapi::OpenApi) {
    let mut openapi = api::ApiDoc::openapi();
    let webauthn_openapi = webauthn::api::openapi_router();
    let (main_router, main_api) = api::openapi_router().split_for_parts();
    openapi.merge(main_api);
    openapi = openapi.nest("/v4", webauthn_openapi.into_openapi());
    (main_router, openapi)
}

/// Serialize `openapi` to stdout in the requested format and return.
///
/// `#[allow(clippy::print_stdout)]`: emitting the schema to stdout is the
/// documented purpose of `--dump-openapi`.
#[allow(clippy::print_stdout)]
pub fn dump_openapi(
    format: &OpenApiFormat,
    openapi: &utoipa::openapi::OpenApi,
) -> Result<(), Report> {
    println!(
        "{}",
        match format {
            OpenApiFormat::Yaml => openapi.to_yaml()?,
            OpenApiFormat::Json => openapi.to_pretty_json()?,
        }
    );
    Ok(())
}
