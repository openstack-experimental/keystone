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

//! Pins the MessagePack layout of the persisted storage types.
//!
//! `rmp_serde::to_vec` encodes structs as positional arrays, so the order in
//! which fields are declared *is* the on-disk and on-wire format: reordering
//! the fields of one of these types (for instance to sort them) silently
//! changes what is written and makes data written before the change
//! unreadable. Every test serializes a value with distinctive field values
//! and compares the bytes to a golden string. When a test fails, do not
//! update the string to make it pass: undo the field reordering, or, if the
//! format has to change on purpose, treat it as a data migration.

use std::fmt::Write;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::audit::AuditRecord;
use crate::local_emergency::DekEmergencyPayload;
use crate::store_command::{MutationInner, PendingRotation, StoreCommand};
use crate::types::Metadata;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// Asserts that `value` serializes to the `expected` hex string and that the
/// golden bytes decode and re-encode to themselves.
pub(crate) fn assert_wire<T: Serialize + DeserializeOwned>(name: &str, value: &T, expected: &str) {
    let bytes = rmp_serde::to_vec(value).unwrap_or_default();
    assert_eq!(
        hex(&bytes),
        expected,
        "{name}: the serialized layout changed; field order is part of the \
         persisted format"
    );
    let decoded: T = rmp_serde::from_slice(&unhex(expected)).unwrap_or_else(|e| {
        panic!("{name}: the golden bytes no longer decode: {e}");
    });
    assert_eq!(
        hex(&rmp_serde::to_vec(&decoded).unwrap_or_default()),
        expected,
        "{name}: decoding and re-encoding the golden bytes changed them"
    );
}

fn metadata() -> Metadata {
    Metadata {
        created_at: 1_700_000_001,
        dek_version: Some(7),
        is_ephemeral: true,
        revision: 42,
        tier: crate::DataTier::Sensitive,
    }
}

#[test]
fn pending_rotation_layout() {
    assert_wire(
        "PendingRotation",
        &PendingRotation {
            dek_version: 9,
            expires_at: 1_700_000_300,
            initiator: "op".into(),
            rotation_id: "rid".into(),
            wrapped_dek: vec![0xAA, 0xBB],
        },
        "95a3726964c402aabb09ce6553f22ca26f70",
    );
}

#[test]
fn dek_emergency_payload_layout() {
    assert_wire(
        "DekEmergencyPayload",
        &DekEmergencyPayload {
            dek_version: 9,
            wrapped_dek: vec![0xAA, 0xBB],
        },
        "9292ccaaccbb09",
    );
}

#[test]
fn store_command_layouts() {
    assert_wire(
        "StoreCommand::RestoreAbort",
        &StoreCommand::RestoreAbort {
            restore_id: "rid".into(),
        },
        "81ac526573746f726541626f727491a3726964",
    );
    assert_wire(
        "StoreCommand::RestoreApply",
        &StoreCommand::RestoreApply {
            restore_id: "rid".into(),
            chunks: 3,
            total_len: 4096,
        },
        "81ac526573746f72654170706c7993a372696403cd1000",
    );
    assert_wire(
        "StoreCommand::RestoreChunk",
        &StoreCommand::RestoreChunk {
            restore_id: "rid".into(),
            seq: 2,
            data: vec![1, 2, 3],
        },
        "81ac526573746f72654368756e6b93a372696402c403010203",
    );
    assert_wire(
        "StoreCommand::Transaction",
        &StoreCommand::Transaction(vec![MutationInner::RemoveIndex { key: vec![1] }]),
        "81ab5472616e73616374696f6e9181ab52656d6f7665496e646578919101",
    );
}

#[test]
fn mutation_inner_layouts() {
    assert_wire(
        "MutationInner::AbortPendingRotation",
        &MutationInner::AbortPendingRotation {
            rotation_id: "rid".into(),
        },
        "81b441626f727450656e64696e67526f746174696f6e91a3726964",
    );
    assert_wire(
        "MutationInner::ClearQuarantine",
        &MutationInner::ClearQuarantine {
            partition: "data".into(),
        },
        "81af436c65617251756172616e74696e6591a464617461",
    );
    assert_wire(
        "MutationInner::ConfirmPendingRotation",
        &MutationInner::ConfirmPendingRotation {
            rotation_id: "rid".into(),
            confirmer: "op2".into(),
        },
        "81b6436f6e6669726d50656e64696e67526f746174696f6e92a3726964a36f7032",
    );
    assert_wire(
        "MutationInner::CreateIfAbsent",
        &MutationInner::CreateIfAbsent {
            cipher: vec![2],
            key: vec![1],
            keyspace: "ks".into(),
            metadata: metadata(),
            tier: 2,
        },
        "81ae4372656174654966416273656e7495c401029101a26b73952ace6553f101a953656e73697469766507c302",
    );
    assert_wire(
        "MutationInner::CreatePendingRotation",
        &MutationInner::CreatePendingRotation {
            rotation_id: "rid".into(),
            wrapped_dek: vec![0xAA, 0xBB],
            dek_version: 9,
            expires_at: 1_700_000_300,
            initiator: "op".into(),
        },
        "81b543726561746550656e64696e67526f746174696f6e95a3726964c402aabb09ce6553f22ca26f70",
    );
    assert_wire(
        "MutationInner::InstallDek",
        &MutationInner::InstallDek {
            wrapped_dek: vec![0xAA, 0xBB],
            dek_version: 9,
            is_emergency: true,
        },
        "81aa496e7374616c6c44656b93c402aabb09c3",
    );
    assert_wire(
        "MutationInner::Quarantine",
        &MutationInner::Quarantine {
            node_id: 3,
            partition: "data".into(),
        },
        "81aa51756172616e74696e659203a464617461",
    );
    assert_wire(
        "MutationInner::Remove",
        &MutationInner::Remove {
            key: vec![1],
            keyspace: "ks".into(),
            expected_revision: Some(3),
        },
        "81a652656d6f7665939101a26b7303",
    );
    assert_wire(
        "MutationInner::RemoveIndex",
        &MutationInner::RemoveIndex { key: vec![1] },
        "81ab52656d6f7665496e646578919101",
    );
    assert_wire(
        "MutationInner::Set",
        &MutationInner::Set {
            cipher: vec![2],
            expected_revision: Some(3),
            key: vec![1],
            keyspace: "ks".into(),
            metadata: metadata(),
            tier: 2,
        },
        "81a353657496c40102039101a26b73952ace6553f101a953656e73697469766507c302",
    );
    assert_wire(
        "MutationInner::SetIndex",
        &MutationInner::SetIndex { key: vec![1] },
        "81a8536574496e646578919101",
    );
}

/// The signed JSON of an audit record is a serialization of the struct, so
/// the key order is part of what the HMAC covers and of what log consumers
/// parse.
#[test]
fn audit_record_json_key_order() {
    let record = AuditRecord {
        actor: "op".into(),
        dek_version: 4,
        details: serde_json::json!({"k": "v"}),
        event_type: "DEK_ROTATION".into(),
        node_id: 3,
        timestamp: 1_700_000_000,
    };
    assert_eq!(
        serde_json::to_string(&record).unwrap_or_default(),
        r#"{"timestamp":1700000000,"event_type":"DEK_ROTATION","actor":"op","node_id":3,"dek_version":4,"details":{"k":"v"}}"#,
        "AuditRecord: the JSON key order changed"
    );
}
