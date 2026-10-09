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

use crate::{DataTier, Metadata, Mutation, StoreDataEnvelope, Violation};

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
fn assert_wire<T: Serialize + DeserializeOwned>(name: &str, value: &T, expected: &str) {
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
        tier: DataTier::Sensitive,
    }
}

#[test]
fn metadata_layout() {
    assert_wire(
        "Metadata",
        &metadata(),
        "952ace6553f101a953656e73697469766507c3",
    );
}

#[test]
fn violation_layout() {
    let violation = Violation {
        description: "d".into(),
        r#type: "t".into(),
        subject: "s".into(),
    };
    assert_wire("Violation", &violation, "93a174a173a164");
}

#[test]
fn store_data_envelope_decodes_data_then_metadata() {
    // The envelope is only deserialized: the golden bytes are what the state
    // machine stores, metadata first and data second.
    let envelope: StoreDataEnvelope<String> = rmp_serde::from_slice(&unhex(
        "92952ace6553f101a953656e73697469766507c3a77061796c6f6164",
    ))
    .unwrap_or_else(|e| {
        panic!("StoreDataEnvelope: the golden bytes no longer decode: {e}");
    });
    assert_eq!(
        envelope,
        StoreDataEnvelope {
            data: "payload".to_string(),
            metadata: metadata(),
        }
    );
}

#[test]
fn mutation_layouts() {
    assert_wire(
        "Mutation::CreateIfAbsent",
        &Mutation::CreateIfAbsent {
            key: vec![1],
            keyspace: "ks".into(),
            metadata: metadata(),
            value: vec![2],
        },
        "81ae4372656174654966416273656e74949101a26b73952ace6553f101a953656e73697469766507c39102",
    );
    assert_wire(
        "Mutation::Remove",
        &Mutation::Remove {
            key: vec![1],
            keyspace: "ks".into(),
            expected_revision: Some(3),
        },
        "81a652656d6f7665939101a26b7303",
    );
    assert_wire(
        "Mutation::RemoveIndex",
        &Mutation::RemoveIndex { key: vec![1] },
        "81ab52656d6f7665496e646578919101",
    );
    assert_wire(
        "Mutation::Set",
        &Mutation::Set {
            expected_revision: Some(3),
            key: vec![1],
            keyspace: "ks".into(),
            metadata: metadata(),
            value: vec![2],
        },
        "81a353657495039101a26b73952ace6553f101a953656e73697469766507c39102",
    );
    assert_wire(
        "Mutation::SetIndex",
        &Mutation::SetIndex { key: vec![1] },
        "81a8536574496e646578919101",
    );
}
