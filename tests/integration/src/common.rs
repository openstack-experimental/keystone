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
//

use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

use eyre::{Result, WrapErr};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbConn, schema::Schema,
};
use tempfile::TempDir;
use uuid::Uuid;

use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone_config::Config;
use openstack_keystone_core::policy::MockPolicy;
use openstack_keystone_core::provider::Provider;
use openstack_keystone_core::resource::ResourceApi;
use openstack_keystone_core::{SqlDriverRegistration, keystone::Service};
use openstack_keystone_core_types::resource::DomainCreate;

/// Setup the database schema.
///
/// Create tables in the order of the foreign references with indexes and types.
pub async fn setup_schema(db: &DbConn) -> Result<()> {
    // TODO: with sea-orm 2.0 it can be improved
    //db.get_schema_registry("crate::db::entity::*").sync(db).await?;
    // Setup Schema helper
    let schema = Schema::new(db.get_database_backend());

    // Iterate over the registered sql plugins and let the create everything they
    // need in the database.
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

pub async fn get_state() -> Result<(Arc<Service>, TempDir)> {
    let db = get_isolated_database().await?;

    let tmp_fernet_repo = TempDir::new()?;

    let mut cfg: Config = Config::default();
    cfg.auth.methods = vec!["application_credential".into(), "password".into()];
    cfg.fernet_tokens.key_repository = tmp_fernet_repo.path().to_path_buf();
    let fernet_utils = openstack_keystone_token_fernet::utils::FernetUtils {
        key_repository: cfg.fernet_tokens.key_repository.clone(),
        max_active_keys: cfg.fernet_tokens.max_active_keys,
    };
    cfg.federation.default_authorization_ttl = 20;
    fernet_utils.initialize_key_repository()?;

    let plugin_manager = PluginManager::with_config(&cfg);
    let provider = Provider::new(cfg.clone(), &plugin_manager)?;

    let state = Arc::new(Service::new(
        cfg,
        db,
        provider,
        Arc::new(MockPolicy::default()),
    )?);

    state
        .provider
        .get_resource_provider()
        .create_domain(
            &state,
            DomainCreate {
                id: Some("<<keystone.domain.root>>".into()),
                name: "<<keystone.domain.root>>".into(),
                enabled: true,
                extra: std::collections::HashMap::new(),
                description: None,
            },
        )
        .await
        .unwrap();
    Ok((state, tmp_fernet_repo))
}

/// Trait to allow State to delete various resource types T
pub trait ResourceDeleter<T>: Send + Sync + 'static {
    fn delete(&self, resource: T) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

pub struct AsyncResourceGuard<T, S>
where
    T: Clone + Send + Sync + 'static,
    S: ResourceDeleter<T> + Clone + Send + Sync + 'static,
{
    pub resource: T,
    pub state: S,
}

impl<T, S> AsyncResourceGuard<T, S>
where
    T: Clone + Send + Sync + 'static,
    S: ResourceDeleter<T> + Clone + Send + Sync + 'static,
{
    pub fn new(resource: T, state: S) -> Self {
        Self { resource, state }
    }

    /// Use this at the end of a test if you want to WAIT for cleanup
    /// instead of letting it happen in the background.
    #[allow(unused)]
    pub async fn cleanup(self) {
        let state = self.state.clone();
        let res = self.resource.clone();
        state.delete(res).await;
        std::mem::forget(self);
    }
}

impl<T, S> Drop for AsyncResourceGuard<T, S>
where
    T: Clone + Send + Sync + 'static,
    S: ResourceDeleter<T> + Clone + Send + Sync + 'static,
{
    fn drop(&mut self) {
        let state = self.state.clone();
        let res = self.resource.clone();

        // Safety net for test panics
        tokio::spawn(async move {
            state.delete(res).await;
        });
    }
}

impl<T, S> Deref for AsyncResourceGuard<T, S>
where
    T: Clone + Send + Sync + 'static,
    S: ResourceDeleter<T> + Clone + Send + Sync + 'static,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.resource
    }
}
