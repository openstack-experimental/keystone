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

use openstack_keystone_storage_crypto::EnvKek;

use super::*;

/// Builds a `FjallStateMachine` for exercising `keyspace_exists` /
/// `drop_keyspace` against the real Fjall backend (as opposed to
/// `mock::MockStorage`, which models the same contract in-memory for
/// driver-level tests).
fn make_sm() -> (FjallStateMachine, tempfile::TempDir) {
    let td = tempfile::TempDir::new().expect("tempdir");
    let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
    let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));
    let epoch = Arc::new(DekEpoch::from_raw(LockedKey::from_raw([0x09; 32]), 1).expect("epoch"));
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
    seed_current_dek(&sm, [0x09; 32], 1);
    (sm, td)
}

#[test]
fn keyspace_exists_is_false_until_first_access_and_never_auto_vivifies() {
    let (sm, _td) = make_sm();
    assert!(!sm.keyspace_exists("rotating_bucket_1"));
    // Checking existence must not have created it as a side effect.
    assert!(!sm.keyspace_exists("rotating_bucket_1"));

    let _ks = sm.keyspace("rotating_bucket_1").expect("create keyspace");
    assert!(sm.keyspace_exists("rotating_bucket_1"));
}

#[test]
fn keyspace_exists_is_always_true_for_core_keyspaces() {
    let (sm, _td) = make_sm();
    assert!(sm.keyspace_exists("data"));
    assert!(sm.keyspace_exists("meta"));
    assert!(sm.keyspace_exists("index"));
}

#[test]
fn drop_keyspace_is_noop_when_never_created() {
    let (sm, _td) = make_sm();
    sm.drop_keyspace("never_created").expect("no-op drop");
    assert!(!sm.keyspace_exists("never_created"));
}

#[test]
fn drop_keyspace_reclaims_an_empty_partition() {
    let (sm, _td) = make_sm();
    sm.keyspace("rotating_bucket_2").expect("create keyspace");
    assert!(sm.keyspace_exists("rotating_bucket_2"));

    sm.drop_keyspace("rotating_bucket_2")
        .expect("drop empty keyspace");
    assert!(!sm.keyspace_exists("rotating_bucket_2"));
}

#[test]
fn drop_keyspace_refuses_non_empty_partition() {
    let (sm, _td) = make_sm();
    let ks = sm.keyspace("rotating_bucket_3").expect("create keyspace");
    ks.insert(b"leftover-key", b"leftover-value")
        .expect("insert");

    let err = sm
        .drop_keyspace("rotating_bucket_3")
        .expect_err("must refuse to drop a non-empty keyspace");
    assert!(matches!(err, StoreError::Other(_)));
    assert!(sm.keyspace_exists("rotating_bucket_3"));
}

#[test]
fn drop_keyspace_refuses_core_keyspaces() {
    let (sm, _td) = make_sm();
    for core in ["data", "meta", "index"] {
        let err = sm
            .drop_keyspace(core)
            .expect_err("must refuse to drop a core keyspace");
        assert!(matches!(err, StoreError::Other(_)));
        assert!(sm.keyspace_exists(core));
    }
}

/// Regression test for the TOCTOU race between `drop_keyspace` and a
/// concurrent `apply()` write: `apply()` holds `keyspace_lifecycle`'s
/// read side for an entry's whole processing+commit, so `drop_keyspace`
/// (which takes the write side) must not be able to proceed while any
/// such read guard is outstanding — otherwise a keyspace could be
/// deleted mid-write, and Fjall's batch-commit path would silently
/// write into the now-deregistered, soon-to-be-discarded partition
/// (it does not consult the `is_deleted` flag the single-item API
/// checks).
#[test]
fn keyspace_lifecycle_lock_excludes_concurrent_readers_and_writer() {
    let (sm, _td) = make_sm();
    sm.keyspace("rotating_bucket_race")
        .expect("create keyspace");

    // Simulate an in-flight apply() holding the read guard for the
    // duration of a batch commit.
    let _apply_guard = sm.keyspace_lifecycle.read().expect("acquire read guard");

    // A concurrent drop_keyspace call must be excluded, not race the
    // in-flight write — try_write proves it would block rather than
    // proceed and silently discard that write.
    assert!(
        sm.keyspace_lifecycle.try_write().is_err(),
        "drop_keyspace's write lock must not be obtainable while apply() holds the read side"
    );
}
