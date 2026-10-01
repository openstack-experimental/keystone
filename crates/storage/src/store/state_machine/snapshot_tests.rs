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

//! Regression coverage for GitHub #1293: `build_snapshot`/`install_snapshot`
//! must carry every replicated Fjall keyspace (`meta`, `index`, dynamic
//! application keyspaces), not just `data`, and `install_snapshot` must
//! clear keyspaces the incoming snapshot no longer carries rather than
//! leaving them stale. These tests drive `build_snapshot`/`install_snapshot`
//! directly against `FjallStateMachine` instances, without a live Raft
//! cluster -- reproducing the full "leader snapshots, a node installs it"
//! scenario is blocked on GitHub #1329 (see issue #1293's discussion).

use openstack_keystone_storage_crypto::EnvKek;

use super::*;

fn make_sm() -> (Arc<FjallStateMachine>, tempfile::TempDir) {
    let td = tempfile::TempDir::new().expect("tempdir");
    let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
    let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));
    let epoch = Arc::new(DekEpoch::from_raw(LockedKey::from_raw([0x21; 32]), 1).expect("epoch"));
    let (reencrypt_tx, reencrypt_rx) = tokio::sync::mpsc::channel(1);
    drop(reencrypt_rx);
    let (quarantine_tx, quarantine_rx) = tokio::sync::mpsc::channel(1);
    drop(quarantine_rx);

    let sm = FjallStateMachine::new(
        db,
        td.path().join("snapshots"),
        1,
        Arc::new(RwLock::new(epoch)),
        Arc::new(Mutex::new(BTreeMap::new())),
        Arc::new(Mutex::new(HashSet::new())),
        kek,
        reencrypt_tx,
        quarantine_tx,
        Arc::new(Mutex::new(HashMap::new())),
    )
    .expect("construct state machine");
    seed_current_dek(&sm, [0x21; 32], 1);
    (Arc::new(sm), td)
}

/// Seeds an ephemeral keyspace directly, mirroring `apply()`'s
/// `Set`/`CreateIfAbsent` arms (see `ephemeral_tests::seed`).
fn seed_ephemeral(sm: &FjallStateMachine, keyspace: &str, key: &[u8]) {
    sm.ephemeral
        .entry(keyspace.to_string())
        .or_default()
        .insert(key.to_vec(), (b"challenge".to_vec(), Metadata::ephemeral()));
}

/// Dumps every entry currently in Fjall keyspace `name`, sorted for
/// deterministic comparison.
fn dump(sm: &FjallStateMachine, name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let ks = sm.keyspace(name).expect("keyspace handle");
    let mut out: Vec<_> = ks
        .iter()
        .filter_map(|item| item.into_inner().ok())
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    out.sort();
    out
}

#[tokio::test]
async fn build_snapshot_captures_every_keyspace_and_ephemeral_registry() {
    let (mut sm, _td) = make_sm();

    sm.data()
        .insert(b"rec1", b"ciphertext")
        .expect("write data");
    let meta_bytes = Metadata::with_tier(DataTier::Internal)
        .pack()
        .expect("pack metadata");
    sm.meta()
        .insert(b"rec1", meta_bytes.clone())
        .expect("write meta");
    sm.index().insert(b"idx1", b"").expect("write index");
    let domain_ks = sm.keyspace("domain").expect("create domain keyspace");
    domain_ks
        .insert(b"dom1", b"domain-payload")
        .expect("write domain");
    seed_ephemeral(&sm, "webauthn_state_1", b"user-1:auth");

    let snapshot = sm.build_snapshot().await.expect("build snapshot");
    let payload: SnapshotPayload =
        rmp_serde::from_slice(&snapshot.snapshot).expect("decode payload");

    assert_eq!(payload.version, SNAPSHOT_FORMAT_VERSION);

    let by_name: HashMap<String, Vec<(Vec<u8>, Vec<u8>)>> = payload.keyspaces.into_iter().collect();
    assert_eq!(
        by_name.get("data"),
        Some(&vec![(b"rec1".to_vec(), b"ciphertext".to_vec())])
    );
    let meta_entries = by_name.get("meta").expect("meta keyspace captured");
    assert!(meta_entries.contains(&(b"rec1".to_vec(), meta_bytes)));
    assert!(
        meta_entries
            .iter()
            .any(|(k, _)| k.as_slice() == META_DEK_CURRENT),
        "the current DEK must travel with the snapshot"
    );
    assert_eq!(
        by_name.get("index"),
        Some(&vec![(b"idx1".to_vec(), b"".to_vec())])
    );
    assert_eq!(
        by_name.get("domain"),
        Some(&vec![(b"dom1".to_vec(), b"domain-payload".to_vec())])
    );
    assert!(
        !by_name.contains_key("logs"),
        "the node-local Raft log keyspace must never travel in a snapshot"
    );
    assert!(
        !by_name.contains_key("local_emergency"),
        "the node-local emergency keyspace (ADR 0028) must never travel in a snapshot"
    );

    assert_eq!(
        payload.ephemeral_keyspaces,
        vec!["webauthn_state_1".to_string()]
    );
}

#[tokio::test]
async fn install_snapshot_replaces_all_keyspaces_and_clears_stale_ones() {
    // "Leader": populate several keyspaces plus an ephemeral
    // registration, then build a snapshot from it.
    let (mut leader, _td1) = make_sm();
    leader
        .data()
        .insert(b"rec1", b"new-cipher")
        .expect("write data");
    let meta_bytes = Metadata::with_tier(DataTier::Internal)
        .pack()
        .expect("pack metadata");
    leader
        .meta()
        .insert(b"rec1", meta_bytes.clone())
        .expect("write meta");
    leader
        .keyspace("domain")
        .expect("create domain keyspace")
        .insert(b"dom1", b"fresh")
        .expect("write domain");
    seed_ephemeral(&leader, "webauthn_state_1", b"user-1:auth");

    let snapshot = leader.build_snapshot().await.expect("build snapshot");

    // "Follower": stale/different data in the same keyspaces, an extra
    // keyspace the leader's snapshot no longer carries, and a stray
    // ephemeral registration -- everything `install_snapshot` must
    // clear (GitHub #1293 point 3).
    let (mut follower, _td2) = make_sm();
    follower
        .data()
        .insert(b"rec1", b"stale-cipher")
        .expect("seed stale data");
    follower
        .data()
        .insert(b"rec-gone", b"should-be-cleared")
        .expect("seed stale-only data key");
    follower
        .meta()
        .insert(b"rec1", b"stale-meta")
        .expect("seed stale meta");
    follower
        .keyspace("project_id")
        .expect("create stale keyspace")
        .insert(b"proj1", b"stale")
        .expect("seed stale project data");
    seed_ephemeral(&follower, "stray_ephemeral", b"leftover");

    follower
        .install_snapshot(&snapshot.meta, snapshot.snapshot.clone())
        .await
        .expect("install snapshot");

    assert_eq!(
        dump(&follower, "data"),
        vec![(b"rec1".to_vec(), b"new-cipher".to_vec())],
        "the stale-only key must be gone and the stale value replaced"
    );
    assert!(
        dump(&follower, "meta").contains(&(b"rec1".to_vec(), meta_bytes)),
        "meta (per-record Metadata) must now travel in the snapshot too"
    );
    assert_eq!(
        dump(&follower, "domain"),
        vec![(b"dom1".to_vec(), b"fresh".to_vec())]
    );
    assert!(
        dump(&follower, "project_id").is_empty(),
        "a keyspace no longer present in the snapshot must end up empty, not stale"
    );

    assert!(follower.is_ephemeral_keyspace("webauthn_state_1"));
    assert!(
        !follower.is_ephemeral_keyspace("stray_ephemeral"),
        "the follower's stale ephemeral registration must not survive install"
    );
}

/// `meta` also holds the node's vote, purge marker and nonce counters;
/// a snapshot built on the leader carries the leader's, which must not
/// overwrite the installing node's own.
#[tokio::test]
async fn install_snapshot_keeps_node_local_meta() {
    let (mut leader, _td1) = make_sm();
    leader
        .meta()
        .insert(KEY_VOTE, b"leader-vote")
        .expect("vote");
    leader
        .meta()
        .insert(KEY_PURGED, b"leader-purged")
        .expect("purged");
    leader
        .meta()
        .insert(b"_meta:nonce_ctr:1", 99u64.to_be_bytes())
        .expect("nonce");
    let snapshot = leader.build_snapshot().await.expect("build snapshot");

    let (mut follower, _td2) = make_sm();
    follower
        .meta()
        .insert(KEY_VOTE, b"follower-vote")
        .expect("vote");
    follower
        .meta()
        .insert(KEY_PURGED, b"follower-purged")
        .expect("purged");
    follower
        .meta()
        .insert(b"_meta:nonce_ctr:1", 7u64.to_be_bytes())
        .expect("nonce");
    follower
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .expect("install snapshot");

    let get = |k: &[u8]| follower.meta().get(k).expect("get").map(|v| v.to_vec());
    assert_eq!(get(KEY_VOTE), Some(b"follower-vote".to_vec()));
    assert_eq!(get(KEY_PURGED), Some(b"follower-purged".to_vec()));
    assert_eq!(get(b"_meta:nonce_ctr:1"), Some(7u64.to_be_bytes().to_vec()));
}

#[tokio::test]
async fn install_snapshot_rejects_unsupported_format_version() {
    let (mut sm, _td) = make_sm();
    sm.data().insert(b"rec1", b"original").expect("seed data");

    let bogus = SnapshotPayload {
        version: SNAPSHOT_FORMAT_VERSION + 1,
        keyspaces: vec![(
            "data".to_string(),
            vec![(b"rec1".to_vec(), b"attacker-controlled".to_vec())],
        )],
        ephemeral_keyspaces: vec![],
    };
    let bytes = rmp_serde::to_vec(&bogus).expect("encode bogus payload");

    let meta = SnapshotMeta {
        last_log_id: None,
        last_membership: Default::default(),
    };
    let err = sm
        .install_snapshot(&meta, bytes)
        .await
        .expect_err("must reject a snapshot format version it doesn't understand");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("version"));

    // The rejected install must not have touched existing state.
    assert_eq!(
        dump(&sm, "data"),
        vec![(b"rec1".to_vec(), b"original".to_vec())]
    );
}

/// Regression test for GitHub #1296 item 1: filenames are
/// `<leader_id>-<index>-<rand>`, and `"1-9-..." > "1-10-..."` as
/// strings, so picking the "latest" snapshot by lexicographically
/// greatest filename picks a stale one once the applied index crosses
/// a digit boundary. `latest_snapshot_path` must instead follow the
/// persisted write-order history, independent of filename content.
/// Regression test for the restore half of GitHub #1298: a backup taken
/// on one cluster must decode and install on a node that bootstrapped
/// its own, different DEK, and that node must afterwards read the
/// restored ciphertext.
#[tokio::test]
async fn backup_restores_into_a_node_with_a_different_dek() {
    let (mut source, _td1) = make_sm();
    let ks = source.data().clone();
    let (ciphertext, version) = source
        .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"secret")
        .expect("encrypt under the source DEK");
    ks.insert(b"k1", &ciphertext).expect("write ciphertext");
    source.build_snapshot().await.expect("build snapshot");
    let blob = fs::read(
        source
            .latest_snapshot_path()
            .expect("lookup")
            .expect("some"),
    )
    .expect("read backup file");

    let (mut target, _td2) = make_sm();
    let other =
        Arc::new(DekEpoch::from_raw(LockedKey::from_raw([0x77; 32]), 1).expect("other epoch"));
    *target.dek.write().unwrap() = other;
    seed_current_dek(&target, [0x77; 32], 1);
    assert!(
        target
            .decrypt_state(
                &ciphertext,
                DataTier::Internal as u8,
                b"data",
                b"k1",
                Some(version)
            )
            .is_err(),
        "precondition: the target's own DEK must not read the source's records"
    );

    let (snapshot, _utc_epoch, dek_version) = target
        .decode_backup_blob(&blob)
        .expect("decode backup blob");
    assert_eq!(dek_version, 1);
    target
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .expect("install snapshot");

    let plaintext = target
        .decrypt_state(
            &ciphertext,
            DataTier::Internal as u8,
            b"data",
            b"k1",
            Some(version),
        )
        .expect("target must read the restored record with the adopted DEK");
    assert_eq!(plaintext.as_slice(), b"secret");
}

/// A backup whose DEKs cannot be unwrapped with the target's KEK must be
/// rejected up front, leaving the target untouched.
#[tokio::test]
async fn backup_with_foreign_kek_is_rejected() {
    let (mut source, _td1) = make_sm();
    source.build_snapshot().await.expect("build snapshot");
    let blob = fs::read(
        source
            .latest_snapshot_path()
            .expect("lookup")
            .expect("some"),
    )
    .expect("read backup file");

    let (mut target, _td2) = make_sm();
    Arc::get_mut(&mut target).expect("unique").kek = Arc::new(EnvKek::from_bytes([0x24u8; 32]));
    assert!(target.decode_backup_blob(&blob).is_err());
}

/// A live restore replaces the data and DEKs but keeps the node's own
/// Raft bookkeeping, tolerates out-of-order chunks, and leaves no
/// staging behind.
#[tokio::test]
async fn live_restore_keeps_local_raft_bookkeeping() {
    let (mut source, _td1) = make_sm();
    let ks = source.data().clone();
    let (ciphertext, version) = source
        .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"secret")
        .expect("encrypt under the source DEK");
    ks.insert(b"k1", &ciphertext).expect("write ciphertext");
    source.build_snapshot().await.expect("build snapshot");
    let blob = fs::read(
        source
            .latest_snapshot_path()
            .expect("lookup")
            .expect("some"),
    )
    .expect("read backup file");

    let (target, _td2) = make_sm();
    seed_current_dek(&target, [0x77; 32], 1);
    target.data().insert(b"stale", b"x").expect("stale key");
    target
        .meta
        .insert(KEY_LAST_APPLIED_LOG, b"local-applied")
        .expect("applied");
    target
        .meta
        .insert(KEY_LAST_MEMBERSHIP, b"local-membership")
        .expect("membership");
    target.meta.insert(KEY_VOTE, b"local-vote").expect("vote");
    target
        .meta
        .insert(KEY_PURGED, b"local-purged")
        .expect("purged");

    let chunks: Vec<&[u8]> = blob.chunks(blob.len() / 3 + 1).collect();
    for (seq, chunk) in chunks.iter().enumerate().rev() {
        target
            .meta
            .insert(restore_stage_key("r1", seq as u32), *chunk)
            .expect("stage chunk");
    }
    target
        .apply_restore("r1", chunks.len() as u32, blob.len() as u64)
        .expect("live restore");

    assert!(target.data().get(b"stale").expect("get").is_none());
    assert_eq!(
        target
            .decrypt_state(
                &ciphertext,
                DataTier::Internal as u8,
                b"data",
                b"k1",
                Some(version)
            )
            .expect("restored record readable")
            .as_slice(),
        b"secret"
    );
    assert_eq!(
        target
            .meta
            .get(KEY_LAST_APPLIED_LOG)
            .expect("get")
            .as_deref(),
        Some(&b"local-applied"[..])
    );
    assert_eq!(
        target
            .meta
            .get(KEY_LAST_MEMBERSHIP)
            .expect("get")
            .as_deref(),
        Some(&b"local-membership"[..])
    );
    assert_eq!(
        target.meta.prefix(RESTORE_STAGE_PREFIX.as_bytes()).count(),
        0,
        "staged chunks must be gone"
    );
    assert_eq!(
        target.meta.get(KEY_VOTE).expect("get").as_deref(),
        Some(&b"local-vote"[..])
    );
    assert_eq!(
        target.meta.get(KEY_PURGED).expect("get").as_deref(),
        Some(&b"local-purged"[..])
    );
    // The DEK the restore displaced stays readable (log entries and
    // old snapshots are still encrypted under it), also after a restart.
    let shadow = target.shadow_deks.lock().expect("lock");
    assert_eq!(shadow.len(), 1);
    assert_eq!(shadow[0].version, 1);
    assert_eq!(target.meta.prefix(DEK_SHADOW_PREFIX.as_bytes()).count(), 1);
}

/// Staged chunks must reach a follower that catches up by snapshot
/// between the chunks and the apply, or its `RestoreApply` would diverge
/// from its peers'.
#[test]
fn snapshot_payload_carries_staged_restore_chunks() {
    let (sm, _td) = make_sm();
    sm.meta
        .insert(restore_stage_key("r1", 0), b"chunk")
        .expect("stage chunk");
    let payload = sm.snapshot_payload().expect("payload");
    let meta = payload
        .keyspaces
        .iter()
        .find(|(name, _)| name == "meta")
        .expect("meta keyspace");
    assert!(
        meta.1
            .iter()
            .any(|(k, _)| k.as_slice() == restore_stage_key("r1", 0).as_slice())
    );
}

/// Backups written before snapshot files carried a DEK manifest (a
/// 20-byte header followed directly by the ciphertext) stay readable.
#[tokio::test]
async fn backup_without_dek_manifest_still_decodes() {
    let (mut sm, _td) = make_sm();
    sm.build_snapshot().await.expect("build snapshot");
    let blob = fs::read(sm.latest_snapshot_path().expect("lookup").expect("some"))
        .expect("read backup file");
    let (_, encrypted) = split_snapshot_manifest(&blob).expect("split");
    let mut legacy = blob[..LEGACY_SNAPSHOT_HEADER_LEN].to_vec();
    legacy.extend_from_slice(encrypted);

    sm.decode_backup_blob(&legacy).expect("legacy layout");
}

/// A restore rejected on apply leaves the state alone and discards its
/// chunks; the node must not treat it as a fatal I/O error.
#[test]
fn rejected_live_restore_is_not_fatal() {
    let (sm, _td) = make_sm();
    sm.meta
        .insert(restore_stage_key("r1", 0), b"not a backup")
        .expect("stage chunk");
    let err = sm
        .apply_restore("r1", 1, 12)
        .expect_err("garbage must be rejected");
    assert!(matches!(err, RestoreError::Rejected(_)), "{err:?}");
    assert_eq!(sm.meta.prefix(RESTORE_STAGE_PREFIX.as_bytes()).count(), 0);
}

/// An incomplete restore is rejected without touching state, and its
/// staged chunks are discarded.
#[tokio::test]
async fn live_restore_with_missing_chunk_is_rejected() {
    let (mut source, _td1) = make_sm();
    source.build_snapshot().await.expect("build snapshot");
    let blob = fs::read(
        source
            .latest_snapshot_path()
            .expect("lookup")
            .expect("some"),
    )
    .expect("read backup file");

    let (target, _td2) = make_sm();
    target.data().insert(b"keep", b"me").expect("seed");
    let half = blob.len() / 2;
    target
        .meta
        .insert(restore_stage_key("r2", 0), &blob[..half])
        .expect("stage chunk 0");
    // chunk 1 never arrives
    assert!(target.apply_restore("r2", 2, blob.len() as u64).is_err());
    assert!(target.data().get(b"keep").expect("get").is_some());
    assert_eq!(
        target.meta.prefix(RESTORE_STAGE_PREFIX.as_bytes()).count(),
        0
    );
}

#[tokio::test]
async fn latest_snapshot_path_follows_write_order_not_filename_sort() {
    let (sm, _td) = make_sm();

    // Write a snapshot whose filename would lexicographically outrank
    // one written after it, if selection were string-based.
    sm.persist_snapshot_file("9-fake-later", b"first-payload", &current_manifest(&sm))
        .expect("write first snapshot file");
    let first_path = sm.latest_snapshot_path().expect("lookup").expect("some");
    assert_eq!(first_path.file_name().unwrap(), "9-fake-later");

    sm.persist_snapshot_file("10-fake-newer", b"second-payload", &current_manifest(&sm))
        .expect("write second snapshot file");
    let second_path = sm.latest_snapshot_path().expect("lookup").expect("some");
    assert_eq!(
        second_path.file_name().unwrap(),
        "10-fake-newer",
        "the more recently written snapshot must be picked even though its \
         filename lexicographically sorts before the older one"
    );
}

/// Regression test for GitHub #1296 item 2: snapshot files were never
/// garbage-collected, so every `build_snapshot` left a full copy of
/// the dataset on disk forever.
#[tokio::test]
async fn old_snapshot_files_are_garbage_collected_beyond_the_retained_history() {
    let (sm, _td) = make_sm();

    for i in 0..(SNAPSHOT_KEEP + 3) {
        sm.persist_snapshot_file(&format!("snap-{i}"), b"payload", &current_manifest(&sm))
            .expect("write snapshot file");
    }

    let remaining: usize = fs::read_dir(sm.snapshot_dir())
        .expect("read snapshot dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .count();
    assert_eq!(
        remaining, SNAPSHOT_KEEP,
        "only the newest {SNAPSHOT_KEEP} snapshot files must survive on disk"
    );
}

/// Regression test for GitHub #1296 item 3: a corrupt or undecryptable
/// newest snapshot file must not prevent startup outright —
/// `get_current_snapshot` must fall back to an older, still-valid
/// retained file.
#[tokio::test]
async fn get_current_snapshot_falls_back_to_an_older_file_if_newest_is_corrupt() {
    let (mut sm, _td) = make_sm();
    sm.data().insert(b"rec1", b"good-data").expect("seed data");

    // First (older, still valid) snapshot.
    let _ = sm.build_snapshot().await.expect("build first snapshot");

    // Second (newest) snapshot, then corrupt it on disk in place.
    let _ = sm.build_snapshot().await.expect("build second snapshot");
    let newest_path = sm
        .latest_snapshot_path()
        .expect("lookup")
        .expect("newest snapshot exists");
    let mut bytes = fs::read(&newest_path).expect("read newest snapshot");
    let tail = bytes.len() - 1;
    bytes[tail] ^= 0xFF; // flip a ciphertext byte -> GCM tag no longer verifies
    fs::write(&newest_path, &bytes).expect("corrupt newest snapshot");

    let snapshot = sm
        .get_current_snapshot()
        .await
        .expect("must not error out")
        .expect("must fall back to the older, still-valid snapshot");
    let payload: SnapshotPayload =
        rmp_serde::from_slice(&snapshot.snapshot).expect("decode payload");
    let by_name: HashMap<String, Vec<(Vec<u8>, Vec<u8>)>> = payload.keyspaces.into_iter().collect();
    assert_eq!(
        by_name.get("data"),
        Some(&vec![(b"rec1".to_vec(), b"good-data".to_vec())])
    );
}
