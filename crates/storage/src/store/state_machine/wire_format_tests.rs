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

//! Pins the MessagePack layout of the persisted state machine types.
//!
//! `rmp_serde::to_vec` encodes structs as positional arrays, so the order in
//! which fields are declared *is* the on-disk and on-wire format: reordering
//! the fields of one of these types (for instance to sort them) silently
//! changes what is written and makes data written before the change
//! unreadable. Every test serializes a value with distinctive field values
//! and compares the bytes to a golden string. When a test fails, do not
//! update the string to make it pass: undo the field reordering, or, if the
//! format has to change on purpose, treat it as a data migration.

use super::rotation::ReencryptProgress;
use super::snapshot_file::SnapshotPayload;
use crate::wire_format_tests::assert_wire;

#[test]
fn reencrypt_progress_layout() {
    assert_wire(
        "ReencryptProgress",
        &ReencryptProgress {
            already_current: 11,
            key: vec![1, 2],
            keyspace: "ks".into(),
            migrated: 22,
            skipped: 33,
        },
        "95a26b73920102160b21",
    );
}

#[test]
fn snapshot_payload_layout() {
    assert_wire(
        "SnapshotPayload",
        &SnapshotPayload {
            ephemeral_keyspaces: vec!["eph".into()],
            keyspaces: vec![("ks".into(), vec![(vec![1], vec![2])])],
            version: 5,
        },
        "93059192a26b7391929101910291a3657068",
    );
}
