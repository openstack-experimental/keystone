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

//! Service construction: key-repository startup checks, database connection,
//! HTTP clients, provider/policy, distributed storage, `ServiceState`, and
//! the best-effort SPIFFE wiring hung off it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use color_eyre::eyre::{Report, Result, WrapErr};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use secrecy::ExposeSecret;
use tokio::spawn;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::{Startup, audit, debug_elapsed};
use crate::config::{Config, ConfigManager, ListenerConfig, RaftTlsConfiguration};
use crate::db_spiffe;
use crate::k8s_auth_client::KeystoneK8sHttpClient;
use crate::keystone::Service as KeystoneServiceState;
use crate::nova_client_impl::KeystoneNovaHttpClient;
use crate::policy::HttpPolicyEnforcer;
use crate::provider::Provider;
use openstack_keystone_core::error::KeystoneError;
use openstack_keystone_core::keystone::{ServiceState, SpiffeHealthStatus};
use openstack_keystone_credential_driver_sql::fernet::FernetKeyRepository;
use openstack_keystone_distributed_storage::{StorageApi, app::Storage};
use openstack_keystone_token_driver_fernet::utils::FernetUtils;

/// Build everything up to and including a wired [`ServiceState`].
pub async fn run(
    cfg_mgr: Arc<ConfigManager>,
    cfg: Config,
    startup_timer: Instant,
) -> Result<Startup, Report> {
    check_fernet_repositories(&cfg).await?;

    let token = CancellationToken::new();

    let conn = connect_database(&cfg).await?;
    let (k8s_http_client, nova_http_client) = init_http_clients(&cfg)?;

    let plugin_manager = crate::plugin_manager::PluginManager::with_config(&cfg)
        .await
        .wrap_err("initializing plugin manager")?;
    debug!("Plugin manager initialized.");

    let provider = Provider::new(&cfg, &plugin_manager, k8s_http_client, nova_http_client)?;
    debug!("Central provider manager initialized.");
    let policy = HttpPolicyEnforcer::new(cfg.api_policy.opa_base_url.clone()).await?;
    debug!("Policy enforcer started.");

    let concrete_storage = init_storage(&cfg_mgr, &cfg).await?;
    let storage_for_service: Option<Arc<dyn StorageApi>> = concrete_storage
        .as_ref()
        .map(Arc::clone)
        .map(|s| s as Arc<dyn StorageApi>);

    let audit_dispatcher = audit::init(&cfg).await?;
    debug_elapsed(startup_timer, "init_audit");

    let state = Arc::new(
        KeystoneServiceState::new(
            cfg_mgr,
            conn,
            provider,
            Arc::new(policy),
            audit_dispatcher,
            storage_for_service,
        )
        .await?,
    );
    debug_elapsed(startup_timer, "ServiceState creation");

    wire_local_emergency_store(&state, &concrete_storage).await;
    wire_spiffe_health(&state, &cfg).await;
    spawn_db_spiffe_writer(&cfg, &token);

    Ok(Startup {
        cfg,
        token,
        state,
        concrete_storage,
    })
}

/// ADR 0019 §4: refuse to start if either Fernet key repository (credential
/// or token) contains the well-known Null Key, unless the operator has
/// explicitly opted in. This is an eager check on top of the lazy one each
/// repository already performs on first access.
async fn check_fernet_repositories(cfg: &Config) -> Result<(), Report> {
    FernetKeyRepository::new(cfg.credential.key_repository.clone())
        .check_startup_null_key(cfg.credential.insecure_allow_null_key)
        .await
        .wrap_err("credential key repository failed startup check")?;

    FernetUtils {
        key_repository: cfg.fernet_tokens.key_repository.clone(),
        max_active_keys: cfg.fernet_tokens.max_active_keys,
    }
    .check_startup_null_key(cfg.fernet_tokens.insecure_allow_null_key)
    .await
    .wrap_err("token key repository failed startup check")?;
    Ok(())
}

/// Open the Sea-ORM database connection, syncing the schema first when the
/// target is an ephemeral in-memory SQLite database.
async fn connect_database(cfg: &Config) -> Result<DatabaseConnection, Report> {
    let opt: ConnectOptions = ConnectOptions::new(cfg.database.get_connection().expose_secret())
        .sqlx_logging(cfg.database.sqlx_logging_enabled())
        .sqlx_logging_level(cfg.database.sqlx_logging_level())
        .to_owned();

    debug!("Establishing the database connection...");
    let conn = Database::connect(opt.clone())
        .await
        .wrap_err("Database connection failed")?;
    if opt.get_url() == "sqlite::memory:" {
        warn!("The database connection represent in-memory SQLite Database.");
        openstack_keystone_core::db::sync_schema(&conn)
            .await
            .wrap_err("failed to sync schema for in-memory database")?;
    }
    debug!("Database connection established.");
    Ok(conn)
}

type K8sHttpClient = Arc<dyn openstack_keystone_core::k8s_auth::K8sHttpClient>;
type NovaHttpClient = Arc<dyn openstack_keystone_core::nova_client::NovaHttpClient>;

/// Construct the outbound HTTP clients the provider needs (Kubernetes
/// TokenReview, Nova vendordata).
fn init_http_clients(cfg: &Config) -> Result<(K8sHttpClient, NovaHttpClient), Report> {
    let k8s_http_client: K8sHttpClient = Arc::new(KeystoneK8sHttpClient::new());
    let nova_http_client: NovaHttpClient = Arc::new(KeystoneNovaHttpClient::new(
        cfg.vendordata.nova_api_base_url.clone(),
        Duration::from_secs(cfg.vendordata.nova_request_timeout_seconds),
    )?);
    Ok((k8s_http_client, nova_http_client))
}

/// Initialize the OpenRaft-backed distributed storage, when
/// `[distributed_storage]` is configured.
async fn init_storage(
    cfg_mgr: &Arc<ConfigManager>,
    cfg: &Config,
) -> Result<Option<Arc<Storage>>, Report> {
    if cfg.distributed_storage.is_none() {
        return Ok(None);
    }
    let storage = openstack_keystone_distributed_storage::app::init_storage(cfg_mgr)
        .await
        .map_err(|e| KeystoneError::Provider {
            source: Box::new(e),
        })?;
    Ok(Some(storage))
}

/// Wire the node-local, quorum-bypass emergency store (ADR 0028) into the
/// shared service state so `--local-quorum-bypass` OAuth2 signing-key
/// rotation can reach it. Same underlying Fjall-backed store DEK's
/// `RotateDekLocalEmergency` RPC writes to, so gossip's periodic sweep sees
/// candidates staged either way.
async fn wire_local_emergency_store(state: &ServiceState, storage: &Option<Arc<Storage>>) {
    if let Some(storage) = storage {
        state
            .set_local_emergency_store(storage.local_emergency_store.clone())
            .await;
    }
}

/// Wire a live SPIFFE `X509Source` into the shared service state, when this
/// deployment has SPIFFE mTLS configured on any interface, so the `/ready`
/// probe's `SpiffeStatus` check can observe SVID freshness.
///
/// Best-effort: a failure here only disables the health signal, it must not
/// block startup — the real mTLS listeners perform their own independent
/// SPIFFE initialization. The `spiffe` crate stays out of
/// `openstack-keystone-core`, so a closure capturing the `X509Source` is
/// handed over, mapped down to `core`'s spiffe-crate-free
/// [`SpiffeHealthStatus`].
async fn wire_spiffe_health(state: &ServiceState, cfg: &Config) {
    if !spiffe_mtls_configured(cfg) {
        return;
    }
    match spiffe::X509Source::new().await {
        Ok(source) => {
            let source = Arc::new(source);
            let check: Arc<dyn Fn() -> SpiffeHealthStatus + Send + Sync> =
                Arc::new(move || match source.svid() {
                    Err(err) => SpiffeHealthStatus::Error(err.to_string()),
                    Ok(_svid) => {
                        if source.is_healthy() {
                            SpiffeHealthStatus::Ok
                        } else {
                            SpiffeHealthStatus::Warn(
                                "SPIFFE X509Source SVID is stale or expired; peer mTLS \
                                 handshakes may be failing silently"
                                    .to_string(),
                            )
                        }
                    }
                });
            state.set_spiffe_health_check(check).await;
        }
        Err(e) => {
            warn!("Failed to initialize SPIFFE X509Source for health checks: {e}");
        }
    }
}

/// Keep `[database]` TLS material fed from Keystone's own SPIFFE SVID/trust
/// bundle when `[database] spiffe_managed = true`. Best-effort: a failure to
/// establish the SPIFFE source only disables this writer, it must not block
/// startup — `Config::finish_load` already validated at config-load time
/// that the three target paths are set.
fn spawn_db_spiffe_writer(cfg: &Config, token: &CancellationToken) {
    if !cfg.database.spiffe_managed {
        return;
    }
    match (
        &cfg.database.tls.tls_cert_file,
        &cfg.database.tls.tls_key_file,
        &cfg.database.tls.tls_client_ca_file,
    ) {
        (Some(cert_file), Some(key_file), Some(ca_file)) => {
            let writer_cfg = db_spiffe::DbSpiffeWriterConfig {
                cert_file: cert_file.clone(),
                key_file: key_file.clone(),
                ca_file: ca_file.clone(),
            };
            let writer_token = token.clone();
            spawn(async move {
                if let Err(error) = db_spiffe::run(writer_token, writer_cfg).await {
                    warn!(%error, "Database SPIFFE writer task failed");
                }
            });
        }
        _ => {
            // Config::finish_load already rejects this combination at load
            // time; reaching here would mean that invariant broke.
            warn!(
                "[database] spiffe_managed = true but tls_cert_file/tls_key_file/\
                 tls_client_ca_file are not all set; skipping the SPIFFE writer task"
            );
        }
    }
}

/// Returns `true` if this deployment has SPIFFE mTLS configured on at least
/// one interface (internal REST, admin UDS, or the Raft gRPC listener).
fn spiffe_mtls_configured(cfg: &Config) -> bool {
    let internal_spiffe = matches!(
        cfg.interface_internal.as_ref().map(|i| &i.listener),
        Some(ListenerConfig::Spiffe(_))
    );
    // The admin interface only ever speaks SPIFFE mTLS over a Unix socket,
    // so its mere presence is enough.
    let admin_spiffe = cfg.interface_admin.is_some();
    let raft_spiffe = matches!(
        cfg.distributed_storage
            .as_ref()
            .map(|ds| &ds.tls_configuration),
        Some(RaftTlsConfiguration::Spiffe(_))
    );
    internal_spiffe || admin_spiffe || raft_spiffe
}
