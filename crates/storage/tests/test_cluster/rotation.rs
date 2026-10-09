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
//! DEK rotation: abort, emergency, concurrent writes, automatic.

use super::harness::*;
use super::*;

/// An `AbortPendingRotation` mutation committed via Raft removes an expired
/// pending emergency rotation so it can no longer be confirmed — exercising
/// the real apply() path for the confirmation-timeout sweeper (ADR 0016-v2
/// §6.2 step 1).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_abort_pending_rotation_via_raft() {
    TypeConfig::run(test_abort_pending_rotation_via_raft_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_abort_pending_rotation_via_raft_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let storage_dir = tempfile::TempDir::new().unwrap();
    let tls_configuration = make_certificates()?;
    let ds_config = get_ds_config(104, storage_dir.path().to_path_buf(), tls_configuration);

    let config = ds_config;

    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    let storage = init_storage(&config_manager(config)).await?;

    storage
        .initialize(
            [(
                104u64,
                openstack_keystone_storage_api::Node {
                    node_id: 104,
                    rpc_addr: "127.0.0.1:0".to_string(),
                },
            )]
            .into_iter()
            .collect(),
        )
        .await?;
    for _ in 0..50 {
        if storage.current_leader() == Some(104) {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(storage.current_leader(), Some(104));

    // Stage an emergency rotation whose confirmation window has already
    // elapsed, exactly as the sweeper would find on its next tick.
    let rotation_id = "test-rotation-abort".to_string();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(10);
    let create_cmd = StoreCommand::Transaction(vec![MutationInner::CreatePendingRotation {
        rotation_id: rotation_id.clone(),
        wrapped_dek: vec![0u8; 60],
        dek_version: 99,
        expires_at,
        initiator: "spiffe://example.org/keystone/storage/operator-a".to_string(),
    }]);
    let create_payload = pb::api::CommandRequest::try_from(create_cmd)?;
    storage.raft.client_write(create_payload).await?;

    // The sweeper proposes exactly this mutation once the window elapses.
    let abort_cmd = StoreCommand::Transaction(vec![MutationInner::AbortPendingRotation {
        rotation_id: rotation_id.clone(),
    }]);
    let abort_payload = pb::api::CommandRequest::try_from(abort_cmd)?;
    storage.raft.client_write(abort_payload).await?;

    // The aborted rotation can no longer be confirmed.
    let confirm_cmd = StoreCommand::Transaction(vec![MutationInner::ConfirmPendingRotation {
        rotation_id: rotation_id.clone(),
        confirmer: "spiffe://example.org/keystone/storage/operator-b".to_string(),
    }]);
    let confirm_payload = pb::api::CommandRequest::try_from(confirm_cmd)?;
    let resp = storage.raft.client_write(confirm_payload).await?;
    assert_eq!(
        resp.data.violations.first().map(|v| v.r#type.as_str()),
        Some("NOT_FOUND"),
        "confirming an aborted rotation must fail with NOT_FOUND, got: {:?}",
        resp.data.violations
    );

    Ok(())
}

/// The sweeper proposes `AbortPendingRotation` through a local, leader-only
/// `client_write` (the `command` RPC rejects admin mutations). A node that is
/// not leader must report `Ok(false)` instead of forwarding; the leader
/// commits it and reports `Ok(true)`.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_propose_abort_pending_rotation_leader_only() {
    TypeConfig::run(test_propose_abort_pending_rotation_leader_only_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_propose_abort_pending_rotation_leader_only_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    // Uninitialized node: not leader, must not forward anywhere.
    let follower_dir = tempfile::TempDir::new().unwrap();
    let follower_config =
        get_ds_config(105, follower_dir.path().to_path_buf(), make_certificates()?);
    let follower = init_storage(&config_manager(follower_config)).await?;
    assert!(!follower.propose_abort_pending_rotation("nope").await?);

    // Single-node leader commits it.
    // The KEK env var is consumed by the first init_storage.
    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }
    let leader_dir = tempfile::TempDir::new().unwrap();
    let leader_config = get_ds_config(106, leader_dir.path().to_path_buf(), make_certificates()?);
    let leader = init_storage(&config_manager(leader_config)).await?;
    leader
        .initialize(
            [(
                106u64,
                openstack_keystone_storage_api::Node {
                    node_id: 106,
                    rpc_addr: "127.0.0.1:0".to_string(),
                },
            )]
            .into_iter()
            .collect(),
        )
        .await?;
    for _ in 0..50 {
        if leader.current_leader() == Some(106) {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(leader.current_leader(), Some(106));
    assert!(leader.propose_abort_pending_rotation("nope").await?);

    Ok(())
}

/// Regression test for GitHub #1299: an emergency (compromised-key) DEK
/// rotation must not make pre-rotation records permanently unreadable.
///
/// Drives the real Raft `apply()` path for the dual-control emergency
/// rotation flow (`CreatePendingRotation` + `ConfirmPendingRotation`, ADR
/// 0016-v2 §6.2), then restarts the node *before* the background
/// re-encryption sweep has had any chance to run -- the worst case, and
/// exactly what the pre-fix code lost forever, since it dropped the
/// revoked key in the same `apply()` call that revoked it. Asserts the
/// record survives both the rotation itself and the restart, and that the
/// revoked key material is eventually discarded once (and only once) the
/// sweep confirms the epoch is fully migrated.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_emergency_dek_rotation_preserves_data_across_restart() {
    TypeConfig::run(test_emergency_dek_rotation_preserves_data_across_restart_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_emergency_dek_rotation_preserves_data_across_restart_inner() -> Result<()> {
    use openstack_keystone_storage_crypto::{EnvKek, KekProvider, generate_dek};

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let storage_dir = tempfile::TempDir::new().unwrap();
    let tls_configuration = make_certificates()?;
    let ds_config = get_ds_config(105, storage_dir.path().to_path_buf(), tls_configuration);

    let config = ds_config;

    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    let storage = init_storage(&config_manager(config.clone())).await?;
    storage
        .initialize(
            [(
                105u64,
                openstack_keystone_storage_api::Node {
                    node_id: 105,
                    rpc_addr: get_addr(105).to_string(),
                },
            )]
            .into_iter()
            .collect(),
        )
        .await?;
    for _ in 0..50 {
        if storage.current_leader() == Some(105) {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(storage.current_leader(), Some(105));

    // Write a record under the bootstrap DEK epoch, before any rotation.
    storage
        .set_value(
            "k1".to_string(),
            make_env("secret-before-rotation")?,
            None,
            None,
        )
        .await?;
    let before = storage
        .get_by_key("k1".as_bytes(), None)
        .await?
        .expect("value present before rotation");
    assert_eq!(
        "secret-before-rotation",
        before.try_deserialize::<String>()?.data
    );

    let (old_version, _) = storage.state_machine_store().current_dek_wrapped()?;

    // Stage + confirm an emergency rotation exactly as the gRPC handlers do
    // (`rotate_dek`/`confirm_rotate_dek`), driving the real Raft `apply()`
    // path for `CreatePendingRotation`/`ConfirmPendingRotation`.
    let kek = EnvKek::from_bytes([0u8; 32]); // matches TEST_KEK_HEX
    let new_raw = generate_dek();
    let wrapped_dek = kek.wrap_dek(new_raw.as_bytes())?;
    let new_version = old_version + 1;
    let rotation_id = "test-emergency-rotation".to_string();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;

    let create_cmd = StoreCommand::Transaction(vec![MutationInner::CreatePendingRotation {
        rotation_id: rotation_id.clone(),
        wrapped_dek,
        dek_version: new_version,
        expires_at,
        initiator: "spiffe://example.org/keystone/storage/operator-a".to_string(),
    }]);
    storage
        .raft
        .client_write(pb::api::CommandRequest::try_from(create_cmd)?)
        .await?;

    let confirm_cmd = StoreCommand::Transaction(vec![MutationInner::ConfirmPendingRotation {
        rotation_id: rotation_id.clone(),
        confirmer: "spiffe://example.org/keystone/storage/operator-b".to_string(),
    }]);
    storage
        .raft
        .client_write(pb::api::CommandRequest::try_from(confirm_cmd)?)
        .await?;

    // The rotation is now live.
    let (current_version, _) = storage.state_machine_store().current_dek_wrapped()?;
    assert_eq!(current_version, new_version);

    // The apply-side audit record must be signed with the *new* epoch's key
    // (GitHub #1300): derive the expected key from the new root DEK and
    // verify the HMAC over the exact record bytes in the spool.
    {
        let expected_key =
            openstack_keystone_storage_crypto::DekEpoch::from_raw(new_raw, new_version)?
                .derive_audit_key(105)?;
        let spool = storage_dir
            .path()
            .join("audit-spool")
            .join("raft-audit-105.jsonl");
        let mut found = None;
        for _ in 0..100 {
            let text = std::fs::read_to_string(&spool).unwrap_or_default();
            found = text
                .lines()
                .find(|l| l.contains(r#""event_type":"DEK_INSTALLED""#))
                .map(str::to_string);
            if found.is_some() {
                break;
            }
            TypeConfig::sleep(Duration::from_millis(50)).await;
        }
        let line = found.expect("DEK_INSTALLED audit record must be spooled");
        let (record, rest) = line
            .strip_prefix(r#"{"record":"#)
            .and_then(|l| l.split_once(r#","key_version":"#))
            .expect("spool line framing");
        let (version, hmac) = rest.split_once(r#","hmac":""#).expect("spool line framing");
        assert_eq!(version, new_version.to_string());
        let mac: String = expected_key
            .sign(record.as_bytes())?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hmac.trim_end_matches(r#""}"#), mac);
    }

    // The pre-rotation record must remain immediately readable. This is the
    // core regression: pre-fix, the old key was dropped and zeroized in the
    // very same `apply()` call that revoked it, before anything could be
    // re-encrypted (#1299) -- this read would have failed (and quarantined
    // the partition) rather than succeeding.
    let still_readable = storage
        .get_by_key("k1".as_bytes(), None)
        .await?
        .expect("value must survive an emergency rotation before the sweep runs");
    assert_eq!(
        "secret-before-rotation",
        still_readable.try_deserialize::<String>()?.data
    );

    // The revoked epoch's key material must be staged on disk so a restart
    // before the sweep completes does not lose it forever.
    let revoked_pending_key = format!("_meta:dek:revoked_pending:{old_version}");
    assert!(
        storage
            .state_machine_store()
            .meta()
            .get(revoked_pending_key.as_bytes())?
            .is_some(),
        "the revoked epoch's key material must be staged for the re-encryption sweep"
    );

    // --- Restart the node *before* giving the background sweep a chance to
    //     run, simulating a crash immediately after the emergency rotation
    //     commits -- the worst case from the issue.
    storage.raft.shutdown().await.ok();
    drop(storage);

    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    // `EnvKek::from_env()` removes the variable after reading it once, so
    // it must be re-set before the restarted node reads it again.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    let storage2 = init_storage(&config_manager(config.clone())).await?;
    for _ in 0..50 {
        if storage2.current_leader() == Some(105) {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(storage2.current_leader(), Some(105));

    // The record, still encrypted on disk under the revoked epoch, must
    // still decrypt after restart: the staged key material survived and
    // was reloaded (`load_revoked_pending_deks`).
    let after_restart = storage2
        .get_by_key("k1".as_bytes(), None)
        .await?
        .expect("value must survive a restart before the sweep completed");
    assert_eq!(
        "secret-before-rotation",
        after_restart.try_deserialize::<String>()?.data
    );

    // Force a snapshot + log purge, exactly as normal Raft operation would
    // eventually do on its own: `finalize_if_revoked` also requires no Raft
    // log entry still reference the revoked epoch before it will discard
    // the key (ADR 0016-v2 §6.2 step 4's other half — the log, not just
    // state records).
    let upto = storage2
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("node must have a non-empty log"))?;
    storage2.raft.trigger().snapshot().await?;
    poll_until(Duration::from_millis(50), 100, || {
        storage2.raft.metrics().borrow_watched().snapshot.is_some()
    })
    .await;
    storage2.raft.trigger().purge_log(upto).await?;
    poll_until(Duration::from_millis(50), 100, || {
        storage2.raft.metrics().borrow_watched().purged.index() >= Some(upto)
    })
    .await;

    // Re-run the sweep now that the log is purged: in production this
    // happens either on the next DEK rotation or via the periodic
    // safety-net retry, but driving it directly here keeps the test fast
    // and deterministic rather than waiting on that timer.
    let mut finalized = false;
    for _ in 0..20 {
        storage2.state_machine_store().reencrypt_pending().await;
        if storage2
            .state_machine_store()
            .meta()
            .get(revoked_pending_key.as_bytes())?
            .is_none()
        {
            finalized = true;
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        finalized,
        "the revoked epoch's staged key material must be discarded once the \
         re-encryption sweep confirms completion"
    );

    // The record remains readable after the revoked epoch is finalized --
    // it was migrated to the current epoch by the sweep.
    let after_sweep = storage2
        .get_by_key("k1".as_bytes(), None)
        .await?
        .expect("value must remain readable after the revoked epoch is finalized");
    assert_eq!(
        "secret-before-rotation",
        after_sweep.try_deserialize::<String>()?.data
    );

    // The permanent, timestamp-only revocation marker is never removed.
    let revoked_key = format!("_meta:dek:revoked:{old_version}");
    assert!(
        storage2
            .state_machine_store()
            .meta()
            .get(revoked_key.as_bytes())?
            .is_some(),
        "the permanent revocation marker must remain after finalization"
    );

    storage2.raft.shutdown().await.ok();
    drop(storage2);
    Ok(())
}

/// M1 exit criterion (#1289): DEK rotations racing concurrent writes (and
/// the background re-encryption sweep, on every node) never revert a
/// committed write (#1295).
const ROTATION_RACE_PORT_BASE: u16 = 900;

#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_rotation_under_concurrent_writes_never_reverts_a_write() {
    TypeConfig::run(async {
        test_rotation_under_concurrent_writes_never_reverts_a_write_inner()
            .await
            .unwrap();
    });
}

async fn test_rotation_under_concurrent_writes_never_reverts_a_write_inner() -> Result<()> {
    use openstack_keystone_storage_crypto::{EnvKek, KekProvider, generate_dek};

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    let (instance1, mut admin_client1) =
        start_single_node_cluster(ROTATION_RACE_PORT_BASE, &tls_configuration).await?;
    let instance2 = join_node2_as_voter(
        ROTATION_RACE_PORT_BASE,
        &tls_configuration,
        &mut admin_client1,
    )
    .await?;

    const NUM_KEYS: usize = 240;
    const WRITERS: usize = 8;
    const ROUNDS: usize = 30;
    const ROTATIONS: u32 = 3;

    for i in 0..NUM_KEYS {
        instance1
            .storage
            .set_value(format!("k{i}"), make_env("seed")?, None, None)
            .await?;
    }
    let (start_version, _) = instance1
        .storage
        .state_machine_store()
        .current_dek_wrapped()?;

    // Each writer exclusively owns the keys `i % WRITERS == w`, so the value
    // it wrote last (and had acknowledged) is the only acceptable final one.
    let writers_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut writer_handles = Vec::new();
    for w in 0..WRITERS {
        let storage = instance1.storage.clone();
        writer_handles.push(tokio::spawn(async move {
            let mut last = BTreeMap::new();
            for round in 1..=ROUNDS {
                for i in (w..NUM_KEYS).step_by(WRITERS) {
                    let value = format!("w{w}r{round}");
                    storage
                        .set_value(format!("k{i}"), make_env(&value)?, None, None)
                        .await?;
                    last.insert(i, value);
                }
            }
            Ok::<_, eyre::Report>(last)
        }));
    }

    // Hammer the local re-encryption sweep on both nodes for as long as the
    // writers run, to maximise overlap with `apply()`.
    let mut sweepers = Vec::new();
    for inst in [instance1.clone(), instance2.clone()] {
        let done = writers_done.clone();
        sweepers.push(tokio::spawn(async move {
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                inst.storage.state_machine_store().reencrypt_pending().await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }

    // Rotate the DEK repeatedly in the middle of the write storm.
    let kek = EnvKek::from_bytes([0u8; 32]); // matches TEST_KEK_HEX
    for n in 1..=ROTATIONS {
        TypeConfig::sleep(Duration::from_millis(150)).await;
        let cmd = StoreCommand::Transaction(vec![MutationInner::InstallDek {
            wrapped_dek: kek.wrap_dek(generate_dek().as_bytes())?,
            dek_version: start_version + n,
            is_emergency: false,
        }]);
        instance1
            .storage
            .raft
            .client_write(pb::api::CommandRequest::try_from(cmd)?)
            .await?;
    }

    let mut expected = BTreeMap::new();
    for h in writer_handles {
        expected.extend(h.await??);
    }
    writers_done.store(true, std::sync::atomic::Ordering::Relaxed);
    for s in sweepers {
        s.await?;
    }
    assert_eq!(NUM_KEYS, expected.len());

    // Let node 2 apply everything, then finish the sweep on both nodes.
    let leader_index = instance1.storage.last_log_index().expect("non-empty log");
    assert!(
        poll_until(Duration::from_millis(100), 200, || {
            instance2.storage.last_log_index() >= Some(leader_index)
        })
        .await,
        "node 2 did not catch up"
    );
    TypeConfig::sleep(Duration::from_millis(300)).await;
    for inst in [&instance1, &instance2] {
        for _ in 0..5 {
            inst.storage.state_machine_store().reencrypt_pending().await;
        }
    }

    // No committed write may have been reverted, on either node, and every
    // record must have been migrated to the newest DEK epoch.
    for inst in [&instance1, &instance2] {
        assert_eq!(
            start_version + ROTATIONS,
            inst.storage.state_machine_store().current_dek_wrapped()?.0
        );
        for (i, want) in &expected {
            let got = inst
                .storage
                .get_by_key(format!("k{i}").as_bytes(), None)
                .await?
                .unwrap_or_else(|| panic!("node {}: k{i} missing", inst.node_id));
            assert_eq!(
                want,
                &got.try_deserialize::<String>()?.data,
                "node {}: committed write to k{i} was reverted",
                inst.node_id
            );
            assert_eq!(
                Some(start_version + ROTATIONS),
                got.metadata.dek_version,
                "node {}: k{i} was not migrated to the newest DEK epoch",
                inst.node_id
            );
        }
    }
    Ok(())
}

/// Automatic DEK rotation (#1301): the leader installs the next version,
/// records its install time, and a second proposal for an already
/// installed version is rejected instead of replacing the DEK.
const AUTO_ROTATION_PORT_BASE: u16 = 1250;

#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_automatic_dek_rotation() {
    TypeConfig::run(async {
        test_automatic_dek_rotation_inner().await.unwrap();
    });
}

async fn test_automatic_dek_rotation_inner() -> Result<()> {
    use openstack_keystone_distributed_storage::app::RotationTrigger;
    use openstack_keystone_storage_crypto::{EnvKek, KekProvider, generate_dek};

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    let (instance, _admin_client) =
        start_single_node_cluster(AUTO_ROTATION_PORT_BASE, &tls_configuration).await?;
    let storage = &instance.storage;
    storage
        .set_value("k".into(), make_env("before")?, None, None)
        .await?;

    let sm = storage.state_machine_store();
    let (start_version, _) = sm.current_dek_wrapped()?;
    assert!(
        sm.dek_installed_at().is_some(),
        "bootstrap epoch has a time"
    );
    assert_eq!(
        None,
        storage.automatic_rotation_due(),
        "a fresh DEK is not due"
    );

    assert!(
        storage
            .rotate_dek_automatically(RotationTrigger::Age { installed_at: 0 })
            .await?
    );
    let (version, _) = sm.current_dek_wrapped()?;
    assert_eq!(start_version + 1, version);
    assert!(sm.dek_installed_at().is_some(), "new epoch has a time");

    // A rotation that lost the race for `version` must not replace it.
    let kek = EnvKek::from_bytes([0u8; 32]); // matches TEST_KEK_HEX
    let cmd = StoreCommand::Transaction(vec![MutationInner::InstallDek {
        wrapped_dek: kek.wrap_dek(generate_dek().as_bytes())?,
        dek_version: version,
        is_emergency: false,
    }]);
    let rsp = storage
        .raft
        .client_write(pb::api::CommandRequest::try_from(cmd)?)
        .await?;
    assert_eq!(
        Some("STALE_DEK_VERSION"),
        rsp.data.violations.first().map(|v| v.r#type.as_str())
    );
    let (after, wrapped_after) = sm.current_dek_wrapped()?;
    assert_eq!(version, after);

    // Data written before the rotations is still readable, and new
    // writes go under the surviving DEK.
    let got = storage.get_by_key(b"k", None).await?;
    assert!(got.is_some());
    storage
        .set_value("k".into(), make_env("after")?, None, None)
        .await?;
    assert_eq!(wrapped_after, sm.current_dek_wrapped()?.1);

    instance.storage.raft.shutdown().await.ok();
    Ok(())
}
