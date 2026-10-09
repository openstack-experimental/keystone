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
//! Node start-up: KEK selection, node-ID uniqueness checks, Raft
//! construction, gRPC routes and DEK adoption for joining nodes.

use super::*;

/// Strip scheme (e.g. "https://") and trailing slash from an rpc_addr so that
/// "https://host:8300/" compares equal to "host:8300".  Both formats encode the
/// same gRPC endpoint and should not trigger uniqueness violations on restart.
pub fn normalize_rpc_addr(addr: &str) -> &str {
    let addr = addr.trim_end_matches('/');
    if let Some(pos) = addr.find("://") {
        // Skip scheme (e.g. "https" in "https://host:8300")
        let rest = &addr[pos + 3..];
        rest.trim_start_matches('/')
    } else {
        addr
    }
}

/// Check that `node_id` is not already registered in the committed cluster
/// membership with a different `rpc_addr`.
///
/// Reads local committed membership state — no network access required.  If
/// the committed membership contains `node_id` at a different address, this
/// indicates a misconfiguration or an impersonation attempt: we refuse to
/// start (fail-closed, per ADR 0016-v2 §4.3 / F7).
async fn check_node_id_uniqueness(
    raft: &Raft,
    node_id: u64,
    rpc_addr: &str,
) -> Result<(), StoreError> {
    let check_addr = normalize_rpc_addr(rpc_addr).to_owned();
    let check_id = node_id;
    let conflict = raft
        .with_raft_state(move |s| {
            s.membership_state
                .committed()
                .nodes()
                .find_map(|(nid, node)| {
                    if *nid == check_id && normalize_rpc_addr(&node.rpc_addr) != check_addr {
                        Some(node.rpc_addr.clone())
                    } else {
                        None
                    }
                })
        })
        .await
        .map_err(|e| StoreError::Other(eyre!("failed to read Raft membership state: {e}")))?;

    if let Some(existing_addr) = conflict {
        tracing::error!(
            node_id,
            rpc_addr,
            existing_addr,
            "FATAL: node_id already registered in cluster at a different address"
        );
        return Err(StoreError::Other(eyre!(
            "FATAL: node_id {node_id} already registered in cluster at {existing_addr}; \
             refusing to start with address {rpc_addr}"
        )));
    }

    tracing::debug!(node_id, rpc_addr, "node_id uniqueness check passed");
    Ok(())
}

/// Best-effort live verification of node_id uniqueness against a reachable
/// cluster peer's *current* membership (ADR 0016-v2 §4.3 / F7).
///
/// `check_node_id_uniqueness` only reads this node's own persisted Raft
/// state, which cannot detect a conflict that appeared on the live cluster
/// while this node was offline (e.g. its old `(node_id, rpc_addr)` was
/// reused by a misconfigured or impersonating node during an outage).
///
/// Returns:
/// - `Ok(true)` if at least one configured peer was reached and its live
///   membership confirms no conflict.
/// - `Ok(false)` if no configured peer could be reached at all — verification
///   is inconclusive. The caller should log a prominent warning but proceed
///   rather than refuse to start: treating "no peer reachable" as fail-closed
///   would make it impossible to recover from a full-cluster outage where every
///   node restarts simultaneously with no live peer to ask (the ADR's literal
///   fail-closed wording does not distinguish that case from an active network
///   partition, so this is a deliberate, documented deviation in favor of
///   cluster recoverability).
/// - `Err` if a reachable peer's live membership shows an actual `(node_id,
///   rpc_addr)` conflict — a real, actionable signal, so this remains
///   fail-closed.
async fn verify_node_id_uniqueness_live(
    tls_client: &RaftTlsClient,
    node_id: u64,
    rpc_addr: &str,
    peers: &[(u64, String)],
) -> Result<bool, StoreError> {
    const PEER_CONTACT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let check_addr = normalize_rpc_addr(rpc_addr);

    for (_peer_id, peer_addr) in peers {
        // Skip only entries that are literally our own address — NOT
        // entries that share our node_id, since a peer advertising our
        // node_id at a *different* address is exactly the conflict this
        // check must detect (skipping on node_id would defeat the purpose
        // whenever a misconfigured node's own retry_join_nodes list still
        // contains the entry for the id it is impersonating).
        if normalize_rpc_addr(peer_addr) == check_addr {
            continue;
        }

        let attempt = async {
            let channel = tls_client.connect(peer_addr).await?;
            let mut client = ClusterAdminServiceClient::new(channel);
            client
                .metrics(())
                .await
                .map(|resp| resp.into_inner())
                .map_err(|s| StoreError::Other(eyre!("metrics RPC failed: {s}")))
        };

        let metrics = match tokio::time::timeout(PEER_CONTACT_TIMEOUT, attempt).await {
            Ok(Ok(metrics)) => metrics,
            Ok(Err(e)) => {
                tracing::debug!(peer_addr, error = %e, "peer unreachable during live uniqueness check");
                continue;
            }
            Err(_) => {
                tracing::debug!(peer_addr, "peer live uniqueness check timed out");
                continue;
            }
        };

        if let Some(membership) = metrics.membership {
            for (nid, node) in &membership.nodes {
                if *nid == node_id && normalize_rpc_addr(&node.rpc_addr) != check_addr {
                    tracing::error!(
                        node_id,
                        rpc_addr,
                        existing_addr = node.rpc_addr,
                        peer_addr,
                        "FATAL: live peer reports node_id already registered at a \
                         different address"
                    );
                    return Err(StoreError::Other(eyre!(
                        "FATAL: node_id {node_id} is registered at {} per live peer {peer_addr}; \
                         refusing to start with address {rpc_addr}",
                        node.rpc_addr
                    )));
                }
            }
        }

        // Reached a peer and found no conflict — verification complete;
        // no need to contact additional peers.
        return Ok(true);
    }

    Ok(false)
}

/// Build the Key Encryption Key provider selected by `ds_config.kek_provider`
/// (ADR 0016-v2 §2.1 / §2.5).
fn build_kek(
    ds_config: &DistributedStorageConfiguration,
) -> Result<Arc<dyn KekProvider>, StoreError> {
    use crate::config::KekProvider as KekProviderKind;

    match ds_config.kek_provider {
        KekProviderKind::Env => {
            if !ds_config.dev_mode {
                return Err(StoreError::Other(eyre!(
                    "kek_provider = \"env\" is only valid when dev_mode = true \
                     (ADR 0016-v2 invariant 6)"
                )));
            }
            if std::env::var("KEYSTONE_ALLOW_ENV_KEK").as_deref() != Ok("1") {
                return Err(StoreError::Other(eyre!(
                    "dev_mode is enabled but KEYSTONE_ALLOW_ENV_KEK=1 is not set; \
                     refusing to start with an environment-provided KEK \
                     (ADR 0016-v2 §2.1, invariant 6)"
                )));
            }
            let kek = EnvKek::from_env()
                .map_err(|e| StoreError::Other(eyre!("failed to load KEYSTONE_DEV_KEK: {e}")))?;
            Ok(Arc::new(kek))
        }
        KekProviderKind::Pkcs11 => build_pkcs11_kek(ds_config),
        KekProviderKind::Tpm => build_tpm_kek(ds_config),
    }
}

/// Open the PKCS#11 KEK from `ds_config.pkcs11` (ADR 0016-v2 §2.5.1).
///
/// `auto_generate` is hardcoded to `false`: whether first-run
/// auto-provisioning of the AES key on the token is acceptable is an
/// operator/deployment decision (regulated environments may require an
/// out-of-band key ceremony instead), so it is not offered as an implicit
/// default here. A dedicated `keystone-manage` provisioning path is a
/// candidate follow-up if auto-provisioning in-process turns out to be
/// wanted.
#[cfg(feature = "pkcs11")]
fn build_pkcs11_kek(
    ds_config: &DistributedStorageConfiguration,
) -> Result<Arc<dyn KekProvider>, StoreError> {
    use secrecy::ExposeSecret;

    use openstack_keystone_storage_crypto_pkcs11::{Pkcs11Kek, Pkcs11KekParams, SlotSelector};

    let cfg = ds_config.pkcs11.as_ref().ok_or_else(|| {
        StoreError::Other(eyre!(
            "kek_provider = \"pkcs11\" requires a [distributed_storage.pkcs11] section"
        ))
    })?;
    let pin = cfg.pkcs11_pin_content.as_ref().ok_or_else(|| {
        StoreError::Other(eyre!("PKCS#11 PIN was not loaded from pkcs11_pin_file"))
    })?;
    let slot = match (&cfg.pkcs11_slot_label, cfg.pkcs11_slot_id) {
        (Some(label), _) => SlotSelector::Label(label.clone()),
        (None, Some(id)) => SlotSelector::Id(id),
        (None, None) => {
            return Err(StoreError::Other(eyre!(
                "[distributed_storage.pkcs11] requires either pkcs11_slot_id or \
                 pkcs11_slot_label"
            )));
        }
    };

    let kek = Pkcs11Kek::open(Pkcs11KekParams {
        module_path: &cfg.pkcs11_module_path,
        slot,
        key_label: &cfg.pkcs11_key_label,
        pin: pin.expose_secret(),
        auto_generate: false,
    })
    .map_err(|e| StoreError::Other(eyre!("failed to open PKCS#11 KEK: {e}")))?;
    Ok(Arc::new(kek))
}

#[cfg(not(feature = "pkcs11"))]
fn build_pkcs11_kek(
    _ds_config: &DistributedStorageConfiguration,
) -> Result<Arc<dyn KekProvider>, StoreError> {
    Err(StoreError::Other(eyre!(
        "kek_provider = \"pkcs11\" was selected but this build was compiled without the \
         `pkcs11` feature"
    )))
}

/// Open the TPM KEK from `ds_config.tpm` (ADR 0016-v2 §2.5.2).
///
/// `auto_generate` is hardcoded to `false` for the same reason as
/// [`build_pkcs11_kek`]. The AES/HMAC child-key pair is located via
/// `tpm_key_handle` (HMAC key at `handle + 1`) or `tpm_key_context_file`
/// (HMAC blobs at `<path>.hmac`) — a convention owned by the
/// `storage-crypto-tpm` crate rather than a second config field, since
/// `TpmKekConfiguration` already carries exactly one key reference and
/// splitting it in two would only matter if an operator needed the two
/// child keys at independently chosen locations, which no deployment has
/// asked for.
#[cfg(feature = "tpm")]
fn build_tpm_kek(
    ds_config: &DistributedStorageConfiguration,
) -> Result<Arc<dyn KekProvider>, StoreError> {
    use secrecy::ExposeSecret;

    use openstack_keystone_storage_crypto_tpm::{KeyReference, TpmKek, TpmKekParams};

    let cfg = ds_config.tpm.as_ref().ok_or_else(|| {
        StoreError::Other(eyre!(
            "kek_provider = \"tpm\" requires a [distributed_storage.tpm] section"
        ))
    })?;
    let key_reference = match (cfg.tpm_key_handle, &cfg.tpm_key_context_file) {
        (Some(handle), _) => KeyReference::PersistentHandle(handle),
        (None, Some(path)) => KeyReference::ContextFile(path.clone()),
        (None, None) => {
            return Err(StoreError::Other(eyre!(
                "[distributed_storage.tpm] requires either tpm_key_handle or \
                 tpm_key_context_file"
            )));
        }
    };
    let auth = cfg.tpm_auth_content.as_ref().map(|s| s.expose_secret());

    let kek = TpmKek::open(TpmKekParams {
        tcti: &cfg.tpm_tcti,
        key_reference,
        auth,
        auto_generate: false,
    })
    .map_err(|e| StoreError::Other(eyre!("failed to open TPM KEK: {e}")))?;
    Ok(Arc::new(kek))
}

#[cfg(not(feature = "tpm"))]
fn build_tpm_kek(
    _ds_config: &DistributedStorageConfiguration,
) -> Result<Arc<dyn KekProvider>, StoreError> {
    Err(StoreError::Other(eyre!(
        "kek_provider = \"tpm\" was selected but this build was compiled without the `tpm` \
         feature"
    )))
}

/// Initialize storage services backed by the raft.
///
/// # Parameters
/// - `config_manager`: Configuration manager.
///
/// # Returns
/// A `Result` containing the `Storage` instance, or a `StoreError`.
pub async fn init_storage(config_manager: &Arc<ConfigManager>) -> Result<Arc<Storage>, StoreError> {
    // Create a configuration for the raft instance.
    let raft_config = Arc::new(
        Config {
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        }
        .validate()?,
    );

    let ds_config = config_manager
        .config
        .read()
        .await
        .view()
        .section::<DistributedStorageConfiguration>()
        .ok_or(StoreError::ConfigMissing)?
        .clone();

    // Select and load the Key Encryption Key before any further
    // initialisation (ADR 0016-v2 §2.1).  Loading/erasing it first means core
    // dumps triggered during preflight cannot leak the key.
    //
    // `ds_config.kek_provider` drives the choice; config-time validation
    // (`validate_kek_selection`) already rejects `env` outside `dev_mode` and
    // missing `pkcs11`/`tpm` sections, but that is a fail-fast, not the sole
    // enforcement point — `build_kek` re-checks at construction time too.
    tracing::debug!(
        node_id = ds_config.node_id,
        path = %ds_config.path.display(),
        "Initializing distributed storage: loading KEK..."
    );
    let kek: Arc<dyn KekProvider> = build_kek(&ds_config)?;
    tracing::debug!("KEK loaded; running preflight checks...");

    // Run OS-level security pre-flight checks after key material is cleared.
    // In production mode (dev_mode = false) any failure is fatal per ADR
    // 0016-v2 §9 / §12 invariant 12.
    crate::preflight::preflight_check(ds_config.dev_mode)
        .map_err(|msg| StoreError::Other(eyre::eyre!("{msg}")))?;

    if ds_config.dev_mode {
        tracing::warn!(
            "Distributed storage starting in dev_mode; production deployments \
             should not enable this (ADR 0016-v2 §12)"
        );
    }

    // Create stores and network
    tracing::debug!("Opening Raft log/state-machine stores...");
    let (
        log_store,
        state_machine_store,
        current_dek,
        _revoked_deks,
        pending_rotations,
        quarantine_rx,
    ) = crate::new::<crate::TypeConfig, _>(ds_config.path.clone(), ds_config.node_id, kek.clone())
        .await?;
    state_machine_store.set_write_rate_threshold(ds_config.write_rate_threshold);
    let log_nonce = log_store.nonce_manager();
    tracing::debug!("Raft stores opened; initializing Raft TLS client...");
    let tls_client = init_tls_watcher(config_manager).await?;
    tracing::debug!("Raft TLS client initialized.");
    let network = Arc::new(NetworkManager::new(tls_client.clone())?);

    // Spawn expiry watchdog for manual-TLS fallback (ADR §4.2). The 30-day
    // max-validity cap itself is enforced inside `get_client_tls_config` /
    // `get_server_tls_config` (network.rs) on every load — including the
    // `init_tls_watcher` call above — so it's checked here on startup and on
    // every subsequent hot-reload, not just once.
    if let RaftTlsConfiguration::Tls(tls) = &ds_config.tls_configuration
        && let Some(cert_content) = tls.tls_cert_content.as_ref()
    {
        use secrecy::ExposeSecret;
        let cert_bytes = cert_content.expose_secret().to_vec();
        CertExpiryWatchdog::spawn(cert_bytes, false);
    }

    // Derive the per-node audit HMAC key from the current DEK epoch (ADR
    // §3.1). The state machine re-derives and installs the key for every
    // later epoch swap (`AuditForwarder::rotate_key`). Attached before the
    // Raft instance starts applying, so no epoch swap can be applied without
    // the forwarder (GitHub #1300).
    let (audit_key_version, audit_key) = {
        let guard = current_dek.read().unwrap_or_else(|p| p.into_inner());
        let key = guard
            .derive_audit_key(ds_config.node_id)
            .map_err(|e| StoreError::Other(eyre!("failed to derive audit HMAC key: {e}")))?;
        (guard.version, key)
    };
    let (audit_forwarder, _audit_task) = AuditForwarder::spawn(
        audit_key_version,
        audit_key,
        AuditSpoolConfig {
            dir: ds_config
                .audit_spool_dir
                .clone()
                .unwrap_or_else(|| ds_config.path.join("audit-spool")),
            node_id: ds_config.node_id,
            max_bytes: ds_config.audit_max_spool_bytes,
        },
    )
    .map_err(|e| StoreError::Other(eyre!("failed to open audit spool: {e}")))?;
    state_machine_store.set_audit_forwarder(audit_forwarder.clone());

    // Create Raft instance
    tracing::debug!("Creating Raft instance...");
    let raft = Raft::new(
        ds_config.node_id,
        raft_config.clone(),
        network.clone(),
        log_store,
        state_machine_store.clone(),
    )
    .await?;

    // ADR 0031 / 0040 metrics: the Raft gauges read the live openraft
    // metrics on every collection; the audit spool exposes its atomics.
    {
        let meter = openstack_keystone_telemetry::metrics::meter();
        let metrics_rx = raft.metrics();
        crate::prometheus_metrics::register_gauges(&meter, ds_config.node_id, move || {
            metrics_rx.borrow_watched().clone()
        });
        audit_forwarder.register_metrics(&meter);

        // Node state is read when metrics are collected. The registration
        // lives as long as the process, so it must not keep the database
        // open: hold the state machine and the nonce manager weakly.
        let state_machine = Arc::downgrade(&state_machine_store);
        let nonce = Arc::downgrade(&log_nonce);
        crate::prometheus_metrics::register_node_status(&meter, move || {
            let mut status = state_machine.upgrade()?.node_status();
            let nonce = nonce.upgrade()?;
            let nonce = nonce.lock().unwrap_or_else(|p| p.into_inner());
            status.log_nonce_counter = Some(nonce.counter());
            status.log_nonce_remaining = Some(nonce.remaining());
            Some(status)
        });
    }

    // Refuse to start if our node_id is already in the cluster under a
    // different address.
    let rpc_addr = ds_config.node_cluster_addr.to_string();
    check_node_id_uniqueness(&raft, ds_config.node_id, &rpc_addr).await?;
    tracing::debug!(
        peers = ds_config.retry_join_nodes.len(),
        "Raft instance created; live peer uniqueness check (if peers configured)..."
    );

    // Additionally verify against a live peer's current membership, since
    // the local check above cannot detect a conflict that appeared while
    // this node was offline (ADR 0016-v2 §4.3 / F7).
    if !ds_config.retry_join_nodes.is_empty() {
        match verify_node_id_uniqueness_live(
            &tls_client,
            ds_config.node_id,
            &rpc_addr,
            &ds_config.retry_join_nodes,
        )
        .await
        {
            Ok(true) => {
                tracing::debug!("node_id uniqueness verified against a live cluster peer");
            }
            Ok(false) => {
                tracing::warn!(
                    node_id = ds_config.node_id,
                    "SECURITY: could not verify node_id uniqueness against any live peer \
                     (ADR 0016-v2 §4.3); proceeding on local state only. If this is a \
                     network partition rather than a full-cluster restart, a duplicate \
                     node_id may go undetected until Raft consensus surfaces it."
                );
            }
            Err(e) => return Err(e),
        }
    }

    let peer_authz = Arc::new(match &ds_config.tls_configuration {
        RaftTlsConfiguration::Spiffe(s) => PeerAuthz::spiffe(
            s.trust_domains.clone(),
            s.spiffe_path_prefix.clone(),
            s.operator_role.clone(),
            s.allowed_peer_svids.clone(),
        ),
        RaftTlsConfiguration::Tls(_) => match &ds_config.tls_role_san_prefix {
            Some(prefix) => PeerAuthz::tls_roles(prefix.clone()),
            None => PeerAuthz::tls_legacy(),
        },
    });

    // ADR 0028: dedicated Fjall keyspace for node-local, quorum-bypass
    // emergency writes, opened off the same database handle the state
    // machine uses but never touched by Raft's `apply()`.
    let local_emergency_store = Arc::new(
        FjallLocalEmergencyStore::new(state_machine_store.db()).map_err(|e| {
            StoreError::Other(eyre!("failed to open local_emergency keyspace: {e}"))
        })?,
    );
    let local_emergency_config = config_manager.config.read().await.local_emergency.clone();

    let storage = Arc::new(Storage {
        connection_pool: DashMap::new(),
        raft,
        node_id: ds_config.node_id,
        state_machine_store,
        tls_client,
        kek,
        current_dek,
        audit_forwarder,
        pending_rotations,
        peer_authz,
        local_emergency_store,
        local_emergency_config,
        ensure_linearizable_retries: ds_config.ensure_linearizable_retries,
        ensure_linearizable_retry_delay_ms: ds_config.ensure_linearizable_retry_delay_ms,
        log_nonce,
        dek_rotation_days: ds_config.dek_rotation_days,
    });

    // Automatic DEK rotation by age and by log nonce volume (ADR 0016-v2
    // §6). Runs on every node but only the leader proposes.
    dek_rotation::spawn_dek_rotation_task(&storage);

    // Best-effort background forwarding of Raft-committed quarantine events
    // (ADR 0016-v2 §10 invariant 5). The local, synchronous quarantine
    // already took effect in FjallStateMachine::decrypt_state before this
    // channel is signalled; this task only propagates the fact cluster-wide.
    //
    // Holds a Weak reference so this task never keeps `Storage` (and the
    // underlying Fjall database handle) alive on its own — once the last
    // strong reference is dropped, the next upgrade() fails and the task
    // exits instead of leaking the node's resources indefinitely.
    {
        let storage_weak = Arc::downgrade(&storage);
        let mut quarantine_rx = quarantine_rx;
        tokio::spawn(async move {
            while let Some((node_id, partition)) = quarantine_rx.recv().await {
                let Some(storage) = storage_weak.upgrade() else {
                    break;
                };
                if let Err(e) = storage.propose_quarantine(node_id, partition.clone()).await {
                    tracing::warn!(
                        node_id,
                        partition,
                        error = %e,
                        "failed to propose quarantine via Raft; local quarantine \
                         remains in effect, cluster-wide visibility delayed"
                    );
                }
            }
        });
    }

    // Emergency-rotation confirmation-timeout sweeper (ADR 0016-v2 §6.2
    // step 1): only the current leader proactively aborts pending
    // emergency rotations whose 5-minute confirmation window has elapsed
    // with no ConfirmRotateDek, so the abort and its audit trail don't
    // depend on some future RPC happening to touch the same rotation_id.
    // Runs on every node but is a no-op unless that node is leader, so
    // exactly one abort (and one audit record) is produced per timeout.
    {
        let storage_weak = Arc::downgrade(&storage);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let Some(storage) = storage_weak.upgrade() else {
                    break;
                };
                if storage.current_leader() != Some(storage.node_id()) {
                    continue;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let expired: Vec<crate::store_command::PendingRotation> = {
                    let pending = storage
                        .pending_rotations
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    pending
                        .values()
                        .filter(|e| e.expires_at <= now)
                        .cloned()
                        .collect()
                };

                for entry in expired {
                    match storage
                        .propose_abort_pending_rotation(&entry.rotation_id)
                        .await
                    {
                        // Lost leadership since the check above: the new
                        // leader's own sweeper handles it.
                        Ok(false) => {}
                        Ok(true) => {
                            storage.audit_forwarder.emit(AuditRecord::now(
                                "DEK_ROTATION_EMERGENCY_ABORTED",
                                &entry.initiator,
                                storage.node_id(),
                                entry.dek_version,
                                serde_json::json!({
                                    "rotation_id": entry.rotation_id,
                                    "expires_at": entry.expires_at,
                                    "reason": "confirmation window expired with no \
                                               ConfirmRotateDek",
                                }),
                            ));
                            tracing::warn!(
                                rotation_id = entry.rotation_id,
                                initiator = entry.initiator,
                                "SECURITY: emergency DEK rotation confirmation window \
                                 expired; automatically aborted"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                rotation_id = entry.rotation_id,
                                error = %e,
                                "failed to propose AbortPendingRotation via Raft"
                            );
                        }
                    }
                }
            }
        });
    }

    // Best-effort periodic gossip sweep (ADR 0028 §5): push every candidate
    // this node originated (not one it adopted via gossip) to every current
    // Raft membership peer, so a candidate staged during a partition still
    // reaches other nodes as reachability changes. Runs regardless of
    // `[local_emergency].enabled`, since gossip itself is not the
    // quorum-bypass write -- only staging a fresh candidate is gated by the
    // guardrail.
    {
        let storage_weak = Arc::downgrade(&storage);
        let gossip_interval = std::time::Duration::from_secs(
            storage
                .local_emergency_config
                .gossip_interval_seconds
                .max(1),
        );
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(gossip_interval);
            ticker.tick().await; // first tick fires immediately; skip it
            loop {
                ticker.tick().await;
                let Some(storage) = storage_weak.upgrade() else {
                    break;
                };
                for subsystem in [
                    openstack_keystone_local_emergency_store::Subsystem::Oauth2SigningKey,
                    openstack_keystone_local_emergency_store::Subsystem::Dek,
                ] {
                    let candidates = match storage
                        .local_emergency_store
                        .list_candidates_for_subsystem(subsystem)
                        .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "local emergency gossip: failed to list candidates"
                            );
                            continue;
                        }
                    };
                    for candidate in candidates
                        .into_iter()
                        .filter(|c| !c.revoked && c.origin_node_id.is_none())
                    {
                        storage.gossip_candidate_to_peers(&candidate).await;
                    }
                }
            }
        });
    }

    Ok(storage)
}

/// Build a tonic `Server` instance for the raft instance.
///
/// # Parameters
/// - `storage`: Reference to the storage instance.
///
/// # Returns
/// A `Result` containing the `Routes`, or a `StoreError`.
pub async fn get_app_server(storage: &Storage) -> Result<Routes, StoreError> {
    let raft_svc_impl = RaftServiceImpl::new(storage.raft.clone(), storage.peer_authz.clone());
    let cluster_admin_svc_impl = ClusterAdminServiceImpl::new(
        storage.raft.clone(),
        storage.node_id,
        storage.kek.clone(),
        storage.current_dek.clone(),
        storage.audit_forwarder.clone(),
        storage.pending_rotations.clone(),
        storage.state_machine_store.clone(),
        storage.peer_authz.clone(),
        storage.local_emergency_store.clone(),
        storage.local_emergency_config.clone(),
    )
    .with_tls_client(storage.tls_client.clone());
    let storage_svc_impl = StorageServiceImpl::new(
        storage.raft.clone(),
        storage.state_machine_store.clone(),
        storage.peer_authz.clone(),
        storage.audit_forwarder.clone(),
        storage.current_dek.clone(),
        storage.node_id,
    );

    let mut router = Routes::builder();
    router
        .add_service(
            RaftServiceServer::new(raft_svc_impl)
                .max_decoding_message_size(crate::RAFT_MAX_MESSAGE_SIZE),
        )
        .add_service(ClusterAdminServiceServer::new(cluster_admin_svc_impl))
        .add_service(StorageServiceServer::new(storage_svc_impl));

    Ok(router.routes())
}

/// Adopts the cluster's current (and retired-but-readable) DEKs from the
/// leader behind `client` into `sm`.
///
/// Must run on a node that is not yet a cluster member, before the leader
/// starts replicating to it, so the node never holds its own
/// bootstrap-generated placeholder DEK once data is replicated to it.
pub(crate) async fn adopt_cluster_dek(
    client: &mut ClusterAdminServiceClient<Channel>,
    sm: &StateMachineStore,
) -> Result<(), StoreError> {
    // Adopt the cluster's current DEK *before* the node is registered as a
    // learner, so this node never holds its own bootstrap-generated
    // placeholder DEK once the leader can start replicating to it
    // (ADR 0016-v2 §2.5.3; GitHub issue #1298: without this, a snapshot
    // installed after log compaction is encrypted under the leader's
    // DEK bytes but this node's same-version epoch has different key
    // bytes, so every decrypt fails GCM verification and the partition
    // gets quarantined). Registering the learner is what causes the leader
    // to start sending replication traffic to this node, so the DEK
    // swap must complete first.
    const FETCH_DEK_ATTEMPTS: u32 = 3;
    const FETCH_DEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let mut fetch_dek_err = None;
    let mut fetch_resp = None;
    for attempt in 1..=FETCH_DEK_ATTEMPTS {
        match tokio::time::timeout(FETCH_DEK_TIMEOUT, client.fetch_dek(())).await {
            Ok(Ok(resp)) => {
                fetch_resp = Some(resp.into_inner());
                break;
            }
            Ok(Err(status)) => {
                fetch_dek_err = Some(eyre!("fetch_dek gRPC call failed: {status}"));
            }
            Err(_) => {
                fetch_dek_err = Some(eyre!(
                    "fetch_dek gRPC call timed out after {FETCH_DEK_TIMEOUT:?}"
                ));
            }
        }
        tracing::warn!(
            attempt,
            max_attempts = FETCH_DEK_ATTEMPTS,
            error = ?fetch_dek_err,
            "fetch_dek attempt failed, retrying"
        );
        if attempt < FETCH_DEK_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_millis(200 * u64::from(attempt))).await;
        }
    }
    let fetch_resp = fetch_resp.ok_or_else(|| {
        StoreError::Other(
            fetch_dek_err.unwrap_or_else(|| eyre!("fetch_dek failed with no error recorded")),
        )
    })?;
    sm.install_fetched_dek(fetch_resp.dek_version, &fetch_resp.wrapped_dek)
        .map_err(|e| {
            StoreError::Other(eyre!(
                "failed to adopt cluster DEK version {}: {e}; this node's KEK material \
                 must be identical to every other cluster node's KEK (ADR 0016-v2 §2.5)",
                fetch_resp.dek_version
            ))
        })?;
    // Also adopt any retired-but-still-readable epochs: a DEK
    // rotation's background re-encryption sweep is best-effort and
    // asynchronous, so records under a retired epoch can still be live
    // when this node joins — without these, decrypting them would fail
    // the same way records under the current epoch would without the
    // fetch above.
    for retired in &fetch_resp.retired {
        sm.install_fetched_retired_dek(retired.dek_version, &retired.wrapped_dek)
            .map_err(|e| {
                StoreError::Other(eyre!(
                    "failed to adopt retired cluster DEK version {}: {e}",
                    retired.dek_version
                ))
            })?;
    }
    if !fetch_resp.retired.is_empty() {
        sm.db().persist(fjall::PersistMode::SyncAll)?;
    }
    tracing::info!(
        dek_version = fetch_resp.dek_version,
        retired_count = fetch_resp.retired.len(),
        "adopted cluster DEK(s) before joining"
    );
    Ok(())
}
