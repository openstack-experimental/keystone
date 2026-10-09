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

//! Shared fixtures for the state machine unit tests.
//!
//! Every `*_tests` module needs a [`FjallStateMachine`] on a throwaway
//! database with a controllable DEK epoch. Building one takes ~20 lines of
//! channel/KEK/lock plumbing, so it lives here once.

use openstack_keystone_storage_crypto::EnvKek;

use super::*;

/// A DEK epoch with a fixed, `seed`-filled key at `version`.
pub(super) fn test_epoch(seed: u8, version: u32) -> Arc<DekEpoch> {
    Arc::new(DekEpoch::from_raw(LockedKey::from_raw([seed; 32]), version).expect("epoch"))
}

/// Builds a `FjallStateMachine` whose current DEK is `current`.
///
/// The DEK is *not* persisted to `meta`, so tests can steer `dek` /
/// `old_deks` directly and simulate a rotation without the Raft apply
/// path. Re-encryption and quarantine receivers are dropped, making
/// signals sent on those channels a no-op. Use [`make_seeded_sm`] when
/// snapshot building (which reads the persisted DEK) is exercised.
pub(super) fn make_sm(current: Arc<DekEpoch>) -> (FjallStateMachine, tempfile::TempDir) {
    let td = tempfile::TempDir::new().expect("tempdir");
    let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
    let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));
    let (reencrypt_tx, reencrypt_rx) = tokio::sync::mpsc::channel(1);
    drop(reencrypt_rx);
    let (quarantine_tx, quarantine_rx) = tokio::sync::mpsc::channel(1);
    drop(quarantine_rx);

    let sm = FjallStateMachine::new(
        db,
        td.path().join("snapshots"),
        1, // node_id
        Arc::new(RwLock::new(current)),
        Arc::new(Mutex::new(BTreeMap::new())),
        Arc::new(Mutex::new(HashSet::new())),
        kek,
        reencrypt_tx,
        quarantine_tx,
        Arc::new(Mutex::new(HashMap::new())),
    )
    .expect("construct state machine");
    (sm, td)
}

/// [`make_sm`] with a version-1 epoch filled with `seed`, also persisted
/// as the node's current DEK (see [`seed_current_dek`]).
pub(super) fn make_seeded_sm(seed: u8) -> (FjallStateMachine, tempfile::TempDir) {
    let (sm, td) = make_sm(test_epoch(seed, 1));
    seed_current_dek(&sm, [seed; 32], 1);
    (sm, td)
}

/// Persists `raw` as the node's current DEK in the `meta` keyspace exactly
/// like `bootstrap_dek` does, which hand-built test state machines skip but
/// snapshot building now requires (the snapshot's DEK manifest is derived
/// from it).
pub(super) fn seed_current_dek(sm: &FjallStateMachine, raw: [u8; 32], version: u32) {
    let wrapped = sm.kek.wrap_dek(&raw).expect("wrap dek");
    let mut persisted = version.to_be_bytes().to_vec();
    persisted.extend_from_slice(&wrapped);
    sm.meta
        .insert(META_DEK_CURRENT, &persisted)
        .expect("persist current dek");
}

/// A manifest naming the state machine's persisted current DEK.
pub(super) fn current_manifest(sm: &FjallStateMachine) -> DekManifest {
    DekManifest {
        current: sm.current_dek_wrapped().expect("current dek"),
        retired: Vec::new(),
    }
}
