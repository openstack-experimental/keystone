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
//! Helpers shared by `keystone-manage` subcommands that connect directly to
//! the database, bypassing the running service.

use std::io;

use color_eyre::eyre::{WrapErr, eyre};
use comfy_table::{ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};
use eyre::Result;
use reqwest::Client;
use sea_orm::ConnectOptions;
use sea_orm::Database;
use sea_orm::DatabaseConnection;
use secrecy::ExposeSecret;
use spiffe_rustls::{authorizer, mtls_client};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    prelude::*,
};

use openstack_keystone_config::Config;

/// Base URL used by [`build_admin_client`]'s Unix-socket-backed client.
pub const ADMIN_BASE_URL: &str = "https://localhost";

/// Install a stderr-writing tracing subscriber at the verbosity implied by
/// `-v` repeats.
///
/// Reports (rather than silently ignoring, or panicking on) a failed
/// install, which happens if a global subscriber is already set — e.g. when
/// a subcommand's tests run in the same process as another's.
pub fn setup_logging(verbose: u8) {
    let filter = Targets::new().with_default(match verbose {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    });

    let log_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_filter(filter);

    if tracing_subscriber::registry()
        .with(log_layer)
        .try_init()
        .is_err()
    {
        eprintln!(
            "warning: a global tracing subscriber was already installed; logging from this \
             command may be incomplete"
        );
    }
}

/// Connect directly to the configured database.
pub async fn connect_db(config: &Config) -> Result<DatabaseConnection> {
    let secret = config.database.get_connection();
    let conn_url = secret.expose_secret().to_string();

    let opt = ConnectOptions::new(conn_url).sqlx_logging(false).to_owned();

    Database::connect(opt)
        .await
        .wrap_err("Database connection failed")
}

/// Build a `reqwest` client that talks to the admin API over the
/// SPIFFE-mTLS Unix socket configured in `[interface_admin]`.
///
/// The returned client should be pointed at [`ADMIN_BASE_URL`].
pub async fn build_admin_client(config: &Config) -> Result<Client> {
    let admin_if = config.interface_admin.as_ref().ok_or_else(|| {
        eyre!("admin interface not configured; this command requires [interface_admin]")
    })?;
    let ks_admin_socket = admin_if.listener.socket_path.clone();

    // Fetch X.509 SVID dynamically from SPIFFE
    let source = spiffe::X509Source::new().await?;

    // Build mTLS ClientConfig with SPIFFE SVID
    let client_config = mtls_client(source.clone())
        .authorize(authorizer::any())
        .build()
        .wrap_err("Building SPIFFE mTLS client config failed")?;

    // Create reqwest client with UDS + SPIFFE mTLS
    Client::builder()
        .unix_socket(ks_admin_socket)
        .tls_backend_preconfigured(client_config)
        .build()
        .wrap_err("Building reqwest client failed")
}

/// Build a `comfy_table::Table` with the project's default styling.
fn new_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

/// Print a collection of resources as a table, one row per resource and one
/// column per attribute.
pub fn print_list_table(headers: Vec<&str>, rows: Vec<Vec<String>>) {
    let mut table = new_table();
    table.set_header(headers);
    for row in rows {
        table.add_row(row);
    }
    println!("{table}");
}

/// Print a single resource as a two-column `Attribute`/`Value` table, one
/// row per attribute.
pub fn print_attribute_table(rows: Vec<(&str, String)>) {
    let mut table = new_table();
    table.set_header(vec!["Attribute", "Value"]);
    for (attribute, value) in rows {
        table.add_row(vec![attribute.to_string(), value]);
    }
    println!("{table}");
}
