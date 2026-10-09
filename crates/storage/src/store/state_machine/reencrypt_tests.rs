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

use super::*;

/// Writes a record the way `apply()` does: ciphertext in the data
/// keyspace plus a matching `Metadata` (with `dek_version` populated) in
/// `meta`. Returns the DEK epoch version the record was encrypted under.
fn write_record(sm: &FjallStateMachine, key: &[u8], plaintext: &[u8]) -> u32 {
    let ks = sm.data().clone();
    let (ciphertext, dek_version) = sm
        .encrypt_and_store(&ks, key, b"data", DataTier::Internal as u8, plaintext)
        .expect("encrypt");
    ks.insert(key, ciphertext).expect("insert ciphertext");
    let mut metadata = Metadata::new();
    metadata.dek_version = Some(dek_version);
    sm.meta()
        .insert(
            meta_key("data", key),
            metadata.pack().expect("pack metadata"),
        )
        .expect("insert metadata");
    dek_version
}

/// End-to-end exercise of ADR 0016-v2 §6 step 5: a record written under
/// a since-retired DEK epoch must be re-encrypted under the current
/// epoch, its `Metadata::dek_version` updated to match, and the epoch
/// marked fully migrated so it isn't re-swept.
#[test]
fn reencrypt_pending_migrates_records_under_retired_epoch() {
    let old_epoch = test_epoch(0x10, 1);
    let (sm, _td) = make_sm(old_epoch.clone());

    let old_version = write_record(&sm, b"k1", b"hello");
    assert_eq!(old_version, old_epoch.version);

    // Simulate a completed rotation exactly as `apply()`'s
    // `MutationInner::InstallDek` handler does: swap in the new current
    // epoch and register the old one for read fallback.
    let new_epoch = test_epoch(0x11, 2);
    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
    sm.old_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version, old_epoch.clone());

    TypeConfig::run(async {
        sm.reencrypt_pending().await;
    });

    // Metadata now names the new epoch.
    let meta_bytes = sm
        .meta()
        .get(meta_key("data", b"k1"))
        .expect("get meta")
        .expect("meta present");
    let metadata = Metadata::unpack(meta_bytes.as_ref()).expect("unpack metadata");
    assert_eq!(metadata.dek_version, Some(new_epoch.version));

    // The record now decrypts under the new epoch's exact hint.
    let stored = sm
        .data()
        .get(b"k1")
        .expect("get data")
        .expect("data present");
    let plaintext = sm
        .decrypt_state(
            stored.as_ref(),
            DataTier::Internal as u8,
            b"data",
            b"k1",
            Some(new_epoch.version),
        )
        .expect("decrypt under new epoch");
    assert_eq!(plaintext, b"hello");

    // A clean pass with nothing skipped marks the epoch done so it's
    // never re-swept (no code path ever writes a new record back under
    // a retired epoch).
    let done_key = format!("{DEK_REENCRYPT_DONE_PREFIX}{}", old_epoch.version);
    assert!(
        sm.meta()
            .get(done_key.as_bytes())
            .expect("get marker")
            .is_some(),
        "fully migrated epoch must be marked done"
    );
}

/// A record already under the current epoch (no rotation pending) must
/// be left untouched by a re-encryption sweep.
#[test]
fn reencrypt_pending_is_noop_with_no_retired_epochs() {
    let epoch = test_epoch(0x12, 1);
    let (sm, _td) = make_sm(epoch);

    write_record(&sm, b"k2", b"hello");
    let before = sm
        .data()
        .get(b"k2")
        .expect("get data")
        .expect("present")
        .to_vec();

    TypeConfig::run(async {
        sm.reencrypt_pending().await;
    });

    let after = sm
        .data()
        .get(b"k2")
        .expect("get data")
        .expect("still present")
        .to_vec();
    assert_eq!(before, after, "no retired epoch to migrate from");
}

/// End-to-end exercise of the fix for GitHub #1299: an emergency-revoked
/// epoch's key material is genuinely discarded only after its
/// re-encryption sweep confirms completion *and* no Raft log entry
/// still references it -- not synchronously at rotation time, the way
/// the pre-fix code did.
#[test]
fn finalize_if_revoked_discards_key_once_swept_and_log_is_clear() {
    let old_epoch = test_epoch(0x20, 1);
    let (sm, _td) = make_sm(old_epoch.clone());

    let old_version = write_record(&sm, b"k1", b"hello");
    assert_eq!(old_version, old_epoch.version);

    // Simulate what the post-commit swap block now does for an
    // emergency rotation: register the old epoch in *both* `old_deks`
    // (still readable during the sweep) and `revoked_deks`
    // (containment), and stage its wrapped bytes on disk the way
    // `InstallDek`'s emergency branch does.
    let new_epoch = test_epoch(0x21, 2);
    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
    // `finalize_if_revoked` builds a snapshot, whose DEK manifest needs
    // the persisted current DEK that `bootstrap_dek` normally writes.
    seed_current_dek(&sm, [0x21; 32], 2);
    sm.old_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version, old_epoch.clone());
    sm.revoked_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version);
    let revoked_pending_key = format!("{DEK_REVOKED_PENDING_PREFIX}{}", old_epoch.version);
    sm.meta()
        .insert(revoked_pending_key.as_bytes(), b"fake-wrapped-bytes")
        .expect("stage revoked-pending key material");

    TypeConfig::run(async {
        sm.reencrypt_pending().await;
    });

    // The record has been migrated and the revoked epoch's key
    // material is genuinely gone -- both in memory and on disk.
    assert!(
        !sm.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&old_epoch.version),
        "finalized revoked epoch must be dropped from old_deks"
    );
    assert!(
        sm.meta()
            .get(revoked_pending_key.as_bytes())
            .expect("get marker")
            .is_none(),
        "staged key material must be deleted once finalized"
    );

    let stored = sm
        .data()
        .get(b"k1")
        .expect("get data")
        .expect("data present");
    let plaintext = sm
        .decrypt_state(
            stored.as_ref(),
            DataTier::Internal as u8,
            b"data",
            b"k1",
            Some(new_epoch.version),
        )
        .expect("record remains readable after finalization");
    assert_eq!(plaintext, b"hello");
}

/// A revoked epoch whose re-encryption swept cleanly but which is still
/// referenced by an un-compacted Raft log entry must not be finalized
/// yet -- discarding the key while a log entry still needs it would
/// make that entry permanently unreadable (GitHub #1299).
#[test]
fn finalize_if_revoked_defers_while_log_entries_remain() {
    let old_epoch = test_epoch(0x22, 1);
    let (sm, _td) = make_sm(old_epoch.clone());

    write_record(&sm, b"k2", b"hello");

    let new_epoch = test_epoch(0x23, 2);
    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch;
    sm.old_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version, old_epoch.clone());
    sm.revoked_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version);
    let revoked_pending_key = format!("{DEK_REVOKED_PENDING_PREFIX}{}", old_epoch.version);
    sm.meta()
        .insert(revoked_pending_key.as_bytes(), b"fake-wrapped-bytes")
        .expect("stage revoked-pending key material");

    // Simulate a still-un-compacted Raft log entry tagged with the
    // revoked version (layout: [dek_version_u32_BE; 4] ++ ...).
    let logs = sm
        .db()
        .keyspace("logs", KeyspaceCreateOptions::default)
        .expect("logs keyspace");
    let mut fake_entry = old_epoch.version.to_be_bytes().to_vec();
    fake_entry.extend_from_slice(&[0u8; 40]);
    logs.insert(1u64.to_be_bytes(), fake_entry)
        .expect("insert fake log entry");

    TypeConfig::run(async {
        sm.reencrypt_pending().await;
    });

    assert!(
        sm.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&old_epoch.version),
        "must not finalize while a log entry still references the revoked epoch"
    );
    assert!(
        sm.meta()
            .get(revoked_pending_key.as_bytes())
            .expect("get marker")
            .is_some(),
        "staged key material must survive while finalization is deferred"
    );
}

/// Regression test for GitHub #1295 (main defect): `reencrypt_one` must
/// hold `keyspace_lifecycle`'s write side for its whole
/// read-decrypt-recompute-commit sequence, so it cannot interleave with
/// a concurrent `apply()` write that, per the fixed doc comment, holds
/// the read side for the same key. Proven the same way as
/// `keyspace_lifecycle_lock_excludes_concurrent_readers_and_writer`
/// proves it for `drop_keyspace`: while a simulated in-flight `apply()`
/// read guard is held on a background thread, a call to `reencrypt_one`
/// on the main thread must block until that guard is released, rather
/// than racing ahead and (as the pre-fix code could) overwriting a
/// write that lands in the gap.
#[test]
fn reencrypt_one_blocks_until_concurrent_apply_guard_is_released() {
    let old_epoch = test_epoch(0x40, 1);
    let (sm, _td) = make_sm(old_epoch.clone());
    let sm = Arc::new(sm);

    write_record(&sm, b"k1", b"hello");

    let new_epoch = test_epoch(0x41, 2);
    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
    sm.old_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version, old_epoch.clone());

    let hold_for = Duration::from_millis(200);
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let sm_bg = sm.clone();
    let released_bg = released.clone();
    let apply_thread = std::thread::spawn(move || {
        // Simulates `apply()` holding the read side of
        // `keyspace_lifecycle` for an entry's whole processing+commit.
        let _guard = sm_bg
            .keyspace_lifecycle
            .read()
            .unwrap_or_else(|p| p.into_inner());
        ready_tx.send(()).expect("signal guard acquired");
        std::thread::sleep(hold_for);
        // Set strictly before the guard drops: if `reencrypt_one` really
        // waits on the lock, it can only return after this is visible.
        released_bg.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    // Deterministically wait until the read guard is held.
    ready_rx
        .recv()
        .expect("apply thread must acquire the guard");

    let ks = sm.data().clone();
    let outcome = sm.reencrypt_one(&ks, "data", b"k1", &old_epoch);
    let was_released = released.load(std::sync::atomic::Ordering::SeqCst);

    apply_thread.join().expect("apply thread must not panic");

    assert!(
        was_released,
        "reencrypt_one must block until the concurrent apply()'s read guard is \
         released instead of racing ahead of it"
    );
    assert!(matches!(outcome, ReencryptOutcome::Migrated));

    let meta_bytes = sm
        .meta()
        .get(meta_key("data", b"k1"))
        .expect("get meta")
        .expect("present");
    let metadata = Metadata::unpack(meta_bytes.as_ref()).expect("unpack metadata");
    assert_eq!(metadata.dek_version, Some(new_epoch.version));
}

/// Stress-test counterpart to the above: many concurrent `apply()`-style
/// writes racing a re-encryption sweep for the same key must never lose
/// a write. This is the scenario GitHub #1295 describes directly: the
/// old code could commit a re-encryption batch that overwrote both the
/// ciphertext and the `Metadata` (including `revision`) of a write
/// `apply()` had already committed, reverting it with no Raft-visible
/// signal. With the fix, `reencrypt_one`'s write-locked critical
/// section and `apply()`'s read-locked one can never interleave, so the
/// final record must always reflect whichever wrote last.
#[test]
fn reencrypt_pending_never_loses_a_concurrent_apply_write() {
    let old_epoch = test_epoch(0x42, 1);
    let (sm, _td) = make_sm(old_epoch.clone());
    let sm = Arc::new(sm);

    write_record(&sm, b"k1", b"v0");

    let new_epoch = test_epoch(0x43, 2);
    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
    sm.old_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version, old_epoch.clone());

    const WRITES: u64 = 50;
    let sm_writer = sm.clone();
    let writer = std::thread::spawn(move || {
        let ks = sm_writer.data().clone();
        for revision in 1..=WRITES {
            let plaintext = format!("v{revision}");
            // Mirrors apply()'s write path: hold the read side of
            // `keyspace_lifecycle` for the whole encrypt+commit.
            let _lifecycle_guard = sm_writer
                .keyspace_lifecycle
                .read()
                .unwrap_or_else(|p| p.into_inner());
            let (ciphertext, dek_version) = sm_writer
                .encrypt_and_store(
                    &ks,
                    b"k1",
                    b"data",
                    DataTier::Internal as u8,
                    plaintext.as_bytes(),
                )
                .expect("encrypt");
            let mut metadata = Metadata::new();
            metadata.revision = revision;
            metadata.dek_version = Some(dek_version);
            let mut batch = sm_writer.db().batch();
            batch.insert(&ks, b"k1".to_vec(), ciphertext);
            batch.insert(
                sm_writer.meta(),
                meta_key("data", b"k1"),
                metadata.pack().expect("pack"),
            );
            batch.commit().expect("commit");
        }
    });

    let sm_reencrypt = sm.clone();
    let reencryptor = std::thread::spawn(move || {
        let ks = sm_reencrypt.data().clone();
        for _ in 0..WRITES {
            sm_reencrypt.reencrypt_one(&ks, "data", b"k1", &old_epoch);
            std::thread::yield_now();
        }
    });

    writer.join().expect("writer thread must not panic");
    reencryptor.join().expect("reencrypt thread must not panic");

    let meta_bytes = sm
        .meta()
        .get(meta_key("data", b"k1"))
        .expect("get meta")
        .expect("present");
    let metadata = Metadata::unpack(meta_bytes.as_ref()).expect("unpack metadata");
    assert_eq!(
        metadata.dek_version,
        Some(new_epoch.version),
        "record must end up under the current epoch"
    );
    assert_eq!(
        metadata.revision, WRITES,
        "the latest committed apply() write's revision must never be reverted \
         by a concurrent re-encryption batch"
    );

    let stored = sm.data().get(b"k1").expect("get data").expect("present");
    let plaintext = sm
        .decrypt_state(
            stored.as_ref(),
            DataTier::Internal as u8,
            b"data",
            b"k1",
            Some(new_epoch.version),
        )
        .expect("decrypt final record");
    assert_eq!(plaintext, format!("v{WRITES}").into_bytes());
}

fn record_dek_version(sm: &FjallStateMachine, key: &[u8]) -> Option<u32> {
    let meta_bytes = sm
        .meta()
        .get(meta_key("data", key))
        .expect("get meta")
        .expect("meta present");
    Metadata::unpack(meta_bytes.as_ref())
        .expect("unpack metadata")
        .dek_version
}

/// A pass interrupted after a checkpoint resumes behind it: records up to
/// the checkpoint are not revisited, the rest are migrated, and the
/// checkpoint is removed once the pass completes.
#[test]
fn reencrypt_pass_resumes_from_checkpoint() {
    let old_epoch = test_epoch(0x30, 1);
    let (sm, _td) = make_sm(old_epoch.clone());
    for key in [b"a", b"b", b"c"] {
        write_record(&sm, key, b"v");
    }

    let new_epoch = test_epoch(0x31, 2);
    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
    sm.old_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version, old_epoch.clone());

    let progress_key = reencrypt_progress_key(1, old_epoch.version);
    sm.save_reencrypt_progress(
        &progress_key,
        &ReencryptProgress {
            keyspace: "data".to_string(),
            key: b"b".to_vec(),
            migrated: 2,
            already_current: 0,
            skipped: 0,
        },
    );

    let report = TypeConfig::run(async { sm.reencrypt_epoch(&old_epoch).await });

    assert_eq!(3, report.migrated, "resumed counts carried over");
    assert_eq!(Some(old_epoch.version), record_dek_version(&sm, b"a"));
    assert_eq!(Some(old_epoch.version), record_dek_version(&sm, b"b"));
    assert_eq!(Some(new_epoch.version), record_dek_version(&sm, b"c"));
    assert!(
        sm.meta()
            .get(progress_key.as_bytes())
            .expect("get")
            .is_none(),
        "checkpoint removed after a completed pass"
    );
}

/// Records skipped before an interruption still keep the epoch from being
/// marked fully migrated, and the following pass starts from the beginning.
#[test]
fn reencrypt_skips_before_checkpoint_block_done_marker() {
    let old_epoch = test_epoch(0x32, 1);
    let (sm, _td) = make_sm(old_epoch.clone());
    write_record(&sm, b"a", b"v");
    write_record(&sm, b"b", b"v");

    let new_epoch = test_epoch(0x33, 2);
    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
    sm.old_deks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(old_epoch.version, old_epoch.clone());

    sm.save_reencrypt_progress(
        &reencrypt_progress_key(1, old_epoch.version),
        &ReencryptProgress {
            keyspace: "data".to_string(),
            key: b"a".to_vec(),
            migrated: 0,
            already_current: 0,
            skipped: 1,
        },
    );

    TypeConfig::run(async { sm.reencrypt_pending().await });
    let done_key = format!("{DEK_REENCRYPT_DONE_PREFIX}{}", old_epoch.version);
    assert!(
        sm.meta().get(done_key.as_bytes()).expect("get").is_none(),
        "a pass with skipped records must not mark the epoch done"
    );
    assert_eq!(Some(old_epoch.version), record_dek_version(&sm, b"a"));

    // The next pass starts over and finishes the epoch.
    TypeConfig::run(async { sm.reencrypt_pending().await });
    assert_eq!(Some(new_epoch.version), record_dek_version(&sm, b"a"));
    assert!(sm.meta().get(done_key.as_bytes()).expect("get").is_some());
}

/// The install time is recorded once per epoch and only reported for the
/// current epoch.
#[test]
fn dek_installed_at_tracks_current_epoch() {
    let epoch = test_epoch(0x34, 1);
    let (sm, _td) = make_sm(epoch);
    assert_eq!(None, sm.dek_installed_at());

    sm.meta()
        .insert(META_DEK_INSTALLED_AT, dek_installed_at_value(1, 1234))
        .expect("insert");
    sm.ensure_dek_installed_at().expect("ensure");
    assert_eq!(Some(1234), sm.dek_installed_at(), "known time kept");

    *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = test_epoch(0x35, 2);
    assert_eq!(None, sm.dek_installed_at(), "time of another epoch");
    sm.ensure_dek_installed_at().expect("ensure");
    assert!(sm.dek_installed_at().is_some_and(|t| t > 1234));
}
