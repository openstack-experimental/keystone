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

fn open_meta() -> (fjall::Keyspace, Arc<Database>, tempfile::TempDir) {
    let td = tempfile::TempDir::new().expect("tempdir");
    let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
    let meta = db
        .keyspace("meta", KeyspaceCreateOptions::default)
        .expect("meta keyspace");
    (meta, db, td)
}

#[test]
fn quarantine_meta_key_puts_partition_before_node_id() {
    assert_eq!(quarantine_meta_key("data", 7), "_meta:quarantine:data:7");
}

#[test]
fn from_meta_only_blocks_matching_node_id() {
    let (meta, db, _td) = open_meta();
    // Node 1's own record blocks; node 2's record is informational only.
    meta.insert(quarantine_meta_key("data", 1), 0u64.to_be_bytes())
        .expect("insert node 1 marker");
    meta.insert(quarantine_meta_key("data", 2), 0u64.to_be_bytes())
        .expect("insert node 2 marker");
    db.persist(PersistMode::SyncAll).expect("persist");

    let tracker = QuarantineTracker::from_meta(&meta, 1).expect("load tracker");
    assert!(tracker.is_quarantined("data"));

    let tracker_other = QuarantineTracker::from_meta(&meta, 2).expect("load tracker");
    assert!(tracker_other.is_quarantined("data"));

    let tracker_uninvolved = QuarantineTracker::from_meta(&meta, 3).expect("load tracker");
    assert!(!tracker_uninvolved.is_quarantined("data"));
}

/// Pre-upgrade quarantine markers (`_meta:quarantine:<partition>`, no
/// node-id suffix) must still block reads after loading, and must be
/// migrated to the node-scoped key format so they survive a *second*
/// restart too — not just silently dropped on `rsplit_once` failure.
#[test]
fn from_meta_migrates_legacy_marker_without_node_id() {
    let (meta, db, _td) = open_meta();
    let legacy_key = format!("{QUARANTINE_META_PREFIX}data");
    meta.insert(legacy_key.as_bytes(), b"1")
        .expect("insert legacy marker");
    db.persist(PersistMode::SyncAll).expect("persist");

    let tracker = QuarantineTracker::from_meta(&meta, 1).expect("load tracker");
    assert!(
        tracker.is_quarantined("data"),
        "legacy marker must still block reads on the node that owns it"
    );

    // The legacy key must have been rewritten to the node-scoped format
    // so a *second* restart doesn't depend on this migration running
    // again.
    assert!(
        meta.get(legacy_key.as_bytes())
            .expect("read legacy key")
            .is_none(),
        "legacy key should have been removed after migration"
    );
    assert!(
        meta.get(quarantine_meta_key("data", 1))
            .expect("read migrated key")
            .is_some(),
        "migrated node-scoped key should now be present"
    );

    let tracker_again = QuarantineTracker::from_meta(&meta, 1).expect("reload tracker");
    assert!(
        tracker_again.is_quarantined("data"),
        "quarantine must still be in effect on a second restart, via the migrated key"
    );
}

#[test]
fn force_quarantine_is_idempotent_with_record_failure() {
    let tracker = QuarantineTracker {
        failures: Mutex::new(HashMap::new()),
        quarantined: Mutex::new(HashSet::new()),
    };
    assert!(!tracker.is_quarantined("data"));
    tracker.force_quarantine("data");
    assert!(tracker.is_quarantined("data"));
    // Calling again is a harmless no-op.
    tracker.force_quarantine("data");
    assert!(tracker.is_quarantined("data"));
}

#[test]
fn clear_removes_quarantine_state() {
    let tracker = QuarantineTracker {
        failures: Mutex::new(HashMap::new()),
        quarantined: Mutex::new(HashSet::new()),
    };
    tracker.force_quarantine("data");
    assert!(tracker.is_quarantined("data"));
    tracker.clear("data");
    assert!(!tracker.is_quarantined("data"));
}

#[test]
fn quarantined_partitions_are_listed_sorted() {
    let tracker = QuarantineTracker {
        failures: Mutex::new(HashMap::new()),
        quarantined: Mutex::new(HashSet::new()),
    };
    assert!(tracker.quarantined_partitions().is_empty());
    tracker.force_quarantine("zeta");
    tracker.force_quarantine("data");
    assert_eq!(
        tracker.quarantined_partitions(),
        vec!["data".to_string(), "zeta".to_string()]
    );
}
