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

//! Regression tests for GitHub #1294: per-record `Metadata` must be
//! namespaced by keyspace, and callers must never be able to write
//! directly into a keyspace reserved for the state machine's own storage.

use openstack_keystone_storage_crypto::EnvKek;

use super::*;

fn test_epoch(seed: u8, version: u32) -> Arc<DekEpoch> {
    Arc::new(DekEpoch::from_raw(LockedKey::from_raw([seed; 32]), version).expect("epoch"))
}

fn make_sm(current: Arc<DekEpoch>) -> (FjallStateMachine, tempfile::TempDir) {
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
        1,
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

#[test]
fn meta_key_never_collides_across_keyspaces_or_with_bare_system_keys() {
    // Two different keyspaces, same record key -> different meta keys.
    assert_ne!(meta_key("data", b"shared"), meta_key("other", b"shared"));
    // The `\0` separator can never be produced by a bare system key
    // (none of them contain a NUL byte), so a namespaced meta key can
    // never collide with one.
    assert_ne!(meta_key("data", b"shared"), META_DEK_CURRENT.to_vec());
    assert!(meta_key("data", b"shared").contains(&0u8));
    assert!(!META_DEK_CURRENT.contains(&0u8));
    assert!(!KEY_LAST_APPLIED_LOG.contains(&0u8));
    assert!(!KEY_LAST_MEMBERSHIP.contains(&0u8));
}

#[test]
fn check_keyspace_allowed_rejects_only_reserved_names() {
    for reserved in RESERVED_KEYSPACES {
        assert!(
            check_keyspace_allowed(reserved).is_err(),
            "'{reserved}' must be rejected as a caller-supplied keyspace"
        );
    }
    for ok in ["data", "identity_users", "oauth2_tokens"] {
        assert!(
            check_keyspace_allowed(ok).is_ok(),
            "'{ok}' must be a valid caller-supplied keyspace"
        );
    }
}

/// Two records with the same key in different keyspaces must have
/// independent `Metadata`: writing/removing one must never affect the
/// other's revision, tier or `dek_version` (GitHub #1294 consequence
/// 1). This mirrors what `apply()`'s `Set`/`Remove` handlers now do via
/// `meta_key`.
#[test]
fn metadata_is_isolated_per_keyspace_for_the_same_record_key() {
    let epoch = test_epoch(0x50, 1);
    let (sm, _td) = make_sm(epoch);

    let ks_a = sm.keyspace("keyspace_a").expect("keyspace a");
    let ks_b = sm.keyspace("keyspace_b").expect("keyspace b");

    let (cipher_a, dek_version_a) = sm
        .encrypt_and_store(
            &ks_a,
            b"shared",
            b"keyspace_a",
            DataTier::Internal as u8,
            b"a",
        )
        .expect("encrypt in keyspace_a");
    ks_a.insert(b"shared", cipher_a).expect("insert a");
    let mut meta_a = Metadata::new();
    meta_a.revision = 7;
    meta_a.dek_version = Some(dek_version_a);
    sm.meta()
        .insert(meta_key("keyspace_a", b"shared"), meta_a.pack().unwrap())
        .expect("insert meta a");

    let (cipher_b, dek_version_b) = sm
        .encrypt_and_store(
            &ks_b,
            b"shared",
            b"keyspace_b",
            DataTier::Internal as u8,
            b"b",
        )
        .expect("encrypt in keyspace_b");
    ks_b.insert(b"shared", cipher_b).expect("insert b");
    let mut meta_b = Metadata::new();
    meta_b.revision = 3;
    meta_b.dek_version = Some(dek_version_b);
    sm.meta()
        .insert(meta_key("keyspace_b", b"shared"), meta_b.pack().unwrap())
        .expect("insert meta b");

    // Removing keyspace_a's record (as apply()'s Remove handler does)
    // must not touch keyspace_b's metadata.
    sm.meta()
        .remove(meta_key("keyspace_a", b"shared"))
        .expect("remove meta a");

    assert!(
        sm.meta()
            .get(meta_key("keyspace_a", b"shared"))
            .expect("get a")
            .is_none(),
        "keyspace_a's metadata must be gone"
    );
    let meta_b_after = sm
        .meta()
        .get(meta_key("keyspace_b", b"shared"))
        .expect("get b")
        .expect("keyspace_b's metadata must survive keyspace_a's removal");
    let unpacked_b = Metadata::unpack(meta_b_after.as_ref()).expect("unpack b");
    assert_eq!(unpacked_b.revision, 3);
    assert_eq!(unpacked_b.dek_version, Some(dek_version_b));
}
