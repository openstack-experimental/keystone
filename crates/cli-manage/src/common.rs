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

use color_eyre::eyre::WrapErr;
use eyre::Result;
use sea_orm::ConnectOptions;
use sea_orm::Database;
use sea_orm::DatabaseConnection;
use secrecy::ExposeSecret;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    prelude::*,
};

use openstack_keystone_config::Config;

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
