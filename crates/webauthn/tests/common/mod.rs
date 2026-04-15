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

#![allow(dead_code)]
use std::sync::Arc;
use std::time;

use eyre::{Result, WrapErr};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbConn, schema::Schema,
};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::{AuthenticatorBackend, WebauthnAuthenticator};

use openstack_keystone_config::{Config, DistributedStorageConfiguration, RelyingParty};
use openstack_keystone_core::SqlDriverRegistration;
use openstack_keystone_core::keystone::Service;
use openstack_keystone_core::policy::{MockPolicy, PolicyEvaluationResult};
use openstack_keystone_core::provider::{Provider, ProviderBuilder};
use openstack_keystone_webauthn::{
    api::{init_extension_state, types::CombinedExtensionState},
    types::*,
};

/// Setup the database schema.
///
/// Create tables in the order of the foreign references with indexes and types.
pub async fn setup_schema(db: &DbConn) -> Result<()> {
    // TODO: with sea-orm 2.0 it can be improved
    //db.get_schema_registry("crate::db::entity::*").sync(db).await?;
    // Setup Schema helper
    let schema = Schema::new(db.get_database_backend());

    //// Iterate over the registered sql plugins and let the create everything they
    //// need in the database.
    for driver in inventory::iter::<SqlDriverRegistration>
        .into_iter()
        .map(|x| x.driver)
    {
        driver.setup(db, &schema).await?;
    }

    Ok(())
}

/// Prepare the isolated Database
///
/// Based on the `DATABASE_URL` environment variable prepare the database for
/// the tests:
///
/// - `postgres` - create a unique schema
/// - `mysql` - create a unique database on the instance
/// - other - use whatever passed.
///
/// By default (when `DATABASE_URL` var is unset) use inmemory sqlite.
pub async fn get_isolated_database() -> Result<DatabaseConnection> {
    let db_conn = std::env::var("DATABASE_URL").unwrap_or("sqlite::memory:".to_string());
    let opts: ConnectOptions = ConnectOptions::new(&db_conn).sqlx_logging(false).to_owned();
    let root_db = Database::connect(opts)
        .await
        .wrap_err_with(|| format!("Failed to connect to database at {}", db_conn.clone()))?;
    let isolated_db_url = if db_conn.starts_with("postgres") {
        // Generate a unique schema name
        let schema_name = format!("test_schema_{}", Uuid::new_v4().simple());

        // Create the schema using a raw SQL driver (sqlx)
        root_db
            .execute_unprepared(&format!("CREATE SCHEMA \"{}\"", schema_name))
            .await
            .expect("Failed to create schema");

        // Create a new connection string that targets this schema specifically
        // Postgres uses 'search_path' to resolve table names
        if db_conn.contains('?') {
            format!("{}&options=-c%20search_path%3D{}", db_conn, schema_name)
        } else {
            format!("{}?options=-c%20search_path%3D{}", db_conn, schema_name)
        }
    } else if db_conn.starts_with("mysql") {
        // Generate a unique database name
        let db_name = format!("test_db_{}", Uuid::new_v4().simple());

        // Create the database
        // MySQL uses backticks for identifiers
        root_db
            .execute_unprepared(&format!("CREATE DATABASE `{}`", db_name))
            .await
            .expect("Failed to create database");

        // Build the connection string for the specific test database
        // Assuming base_url is "mysql://user:pass@localhost:3306"
        format!("{}/{}", db_conn.trim_end_matches('/'), db_name)
    } else {
        // Just use whichever URL has been passed
        db_conn
    };
    let opts = ConnectOptions::new(&isolated_db_url)
        .sqlx_logging(false)
        .to_owned();
    let db = Database::connect(opts).await.wrap_err_with(|| {
        format!(
            "Failed to connect to dedicated database at {}",
            isolated_db_url.clone()
        )
    })?;
    setup_schema(&db).await?;

    Ok(db)
}

pub async fn get_state(
    provider_builder: Option<ProviderBuilder>,
) -> Result<(CombinedExtensionState, TempDir)> {
    let tmp_db_dir = TempDir::new()?;
    let mut cfg: Config = Config::default();
    cfg.webauthn.enabled = true;
    cfg.webauthn.relying_party = Some(RelyingParty {
        id: "local".into(),
        origin: "https://keystone.local".parse()?,
        name: Some("keystone".into()),
    });
    cfg.auth.methods = vec!["application_credential".into(), "password".into()];
    if std::env::var("DATABASE_URL").is_err() {
        cfg.distributed_storage = Some(DistributedStorageConfiguration {
            cluster_addr: "127.0.0.1:12345".into(),
            node_id: 1,
            path: tmp_db_dir.path().to_path_buf(),
            disable_tls: true,
            tls_configuration: None,
        });
    }
    let mut policy_enforcer_mock = MockPolicy::default();

    policy_enforcer_mock
        .expect_enforce()
        .returning(move |_, _, _, _| Ok(PolicyEvaluationResult::allowed()));

    let db = if std::env::var("DATABASE_URL").is_ok() {
        cfg.webauthn.driver = "sql".to_string();
        get_isolated_database().await?
    } else {
        cfg.webauthn.driver = "raft".to_string();
        DatabaseConnection::Disconnected
    };
    let main_state = Arc::new(
        Service::new(
            cfg,
            db,
            provider_builder
                .unwrap_or(Provider::mocked_builder())
                .build()
                .unwrap(),
            Arc::new(policy_enforcer_mock),
        )
        .await
        .unwrap(),
    );
    if let Some(store) = &main_state.storage {
        store
            .raft
            .initialize(std::collections::BTreeMap::from([(
                1u64,
                openstack_keystone_distributed_storage::pb::raft::Node {
                    node_id: 1,
                    rpc_addr: "127.0.0.1:12345".into(),
                },
            )]))
            .await?;
    }
    std::thread::sleep(time::Duration::from_millis(200));

    let cancellation_token = CancellationToken::new();
    let extension_state = init_extension_state(main_state.clone(), cancellation_token.clone())?;
    Ok((extension_state, tmp_db_dir))
}

pub fn generate_webauthn_credential<T: AuthenticatorBackend>(
    state: &CombinedExtensionState,
    authenticator: &mut WebauthnAuthenticator<T>,
    user_id: Uuid,
) -> Result<WebauthnCredential> {
    let origin = Url::parse("https://keystone.local")?;
    let (ccr, reg_state) = state.extension.webauthn.start_passkey_registration(
        user_id,
        "user_name",
        "user_name",
        None,
    )?;

    let reg_result = authenticator.do_registration(origin.clone(), ccr)?;

    let cred = WebauthnCredential::from_passkey(
        state
            .extension
            .webauthn
            .finish_passkey_registration(&reg_result, &reg_state)?,
        user_id,
        Some("descr"),
    );
    Ok(cred)
}
