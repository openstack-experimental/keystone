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
use clap::{Parser, Subcommand};
use color_eyre::Report;
use eyre::WrapErr;
use secrecy::ExposeSecret;
use std::io;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    prelude::*,
};

use sea_orm::ConnectOptions;
use sea_orm::Database;

use sea_orm_migration::prelude::*;

use openstack_keystone::config::Config;
use openstack_keystone::db_migration::Migrator;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Path to the keystone config file.
    #[arg(short, long, default_value = "/etc/keystone/keystone.conf")]
    config: PathBuf,

    /// Verbosity level. Repeat to increase level.
    #[arg(short, long, global=true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply pending migrations.
    Up {
        /// Number of pending migrations to apply.
        #[arg(short('n'))]
        steps: Option<u32>,
    },
    /// Rollback applied migrations.
    Down {
        /// Number of migrations to rollback.
        #[arg(short('n'))]
        steps: Option<u32>,
    },
    /// Check the status of all migrations.
    Status,
    /// Drop all tables from the database, then reapply all migrations.
    Fresh,
    /// Rollback all applied migrations, then reapply all migrations.
    Refresh,
    /// Rollback all applied migrations.
    Reset,
}

#[allow(clippy::print_stdout)]
#[tokio::main]
async fn main() -> Result<(), Report> {
    let cli = Cli::parse();

    let filter = Targets::new().with_default(match cli.verbose {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    });

    let log_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_filter(filter);

    // build the tracing registry
    tracing_subscriber::registry().with(log_layer).init();
    let cfg = Config::new(cli.config)?;
    let opt: ConnectOptions = ConnectOptions::new(cfg.database.get_connection().expose_secret())
        // Prevent dumping the password in plaintext.
        .sqlx_logging(false)
        .to_owned();

    info!("Establishing the database connection...");
    let conn = Database::connect(opt)
        .await
        .wrap_err("Database connection failed")?;

    match cli.command {
        Commands::Up { steps } => {
            Migrator::up(&conn, steps).await?;
        }
        Commands::Down { steps } => {
            Migrator::down(&conn, steps).await?;
        }
        Commands::Status => {
            let migrations = Migrator::get_pending_migrations(&conn).await?;
            if migrations.is_empty() {
                println!("No pending migrations!");
            } else {
                println!("Pending migrations:");
                for mig in migrations {
                    println!("{}", mig.name());
                }
            }
            let migrations = Migrator::get_applied_migrations(&conn).await?;
            println!("Applied migrations:");
            for mig in migrations {
                println!("{}", mig.name());
            }
        }
        Commands::Fresh => {
            Migrator::fresh(&conn).await?;
        }
        Commands::Refresh => {
            Migrator::refresh(&conn).await?;
        }
        Commands::Reset => {
            Migrator::reset(&conn).await?;
        }
    }
    Ok(())
}
