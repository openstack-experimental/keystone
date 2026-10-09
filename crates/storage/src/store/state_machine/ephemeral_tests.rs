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

/// Directly seeds an ephemeral keyspace the way `apply()`'s `Set`/
/// `CreateIfAbsent` arms would, without needing to drive a full
/// `RaftStateMachine::apply()` entry stream — the helper methods under
/// test (`is_ephemeral_keyspace`, `ephemeral_get`, `ephemeral_prefix`,
/// `keyspace_exists`, `drop_keyspace`) are exercised the same way
/// regardless of what populated the map.
fn seed(sm: &FjallStateMachine, keyspace: &str, key: &[u8], value: &[u8], metadata: Metadata) {
    sm.ephemeral
        .entry(keyspace.to_string())
        .or_default()
        .insert(key.to_vec(), (value.to_vec(), metadata));
}

#[test]
fn ephemeral_write_never_touches_the_fjall_db() {
    let (sm, _td) = make_seeded_sm(0x09);
    seed(
        &sm,
        "webauthn_state_1",
        b"user-1:auth",
        b"challenge-bytes",
        Metadata::ephemeral(),
    );

    assert!(sm.keyspace_exists("webauthn_state_1"));
    assert!(sm.is_ephemeral_keyspace("webauthn_state_1"));
    // The keyspace must not exist as a real Fjall partition.
    assert!(!sm.db.keyspace_exists("webauthn_state_1"));
}

#[test]
fn ephemeral_get_round_trips_value_and_metadata() {
    let (sm, _td) = make_seeded_sm(0x09);
    let metadata = Metadata::ephemeral();
    seed(
        &sm,
        "webauthn_state_1",
        b"user-1:auth",
        b"payload",
        metadata,
    );

    let (value, got_metadata) = sm
        .ephemeral_get("webauthn_state_1", b"user-1:auth")
        .expect("value present");
    assert_eq!(value, b"payload");
    assert!(got_metadata.is_ephemeral);
}

#[test]
fn ephemeral_get_is_none_for_unknown_keyspace() {
    let (sm, _td) = make_seeded_sm(0x09);
    assert!(sm.ephemeral_get("never_written", b"any-key").is_none());
    assert!(!sm.is_ephemeral_keyspace("never_written"));
}

#[test]
fn ephemeral_prefix_filters_by_prefix_and_is_none_for_non_ephemeral_keyspace() {
    let (sm, _td) = make_seeded_sm(0x09);
    seed(
        &sm,
        "webauthn_state_1",
        b"user-1:auth",
        b"a",
        Metadata::ephemeral(),
    );
    seed(
        &sm,
        "webauthn_state_1",
        b"user-1:registration",
        b"b",
        Metadata::ephemeral(),
    );
    seed(
        &sm,
        "webauthn_state_1",
        b"user-2:auth",
        b"c",
        Metadata::ephemeral(),
    );

    let matched = sm
        .ephemeral_prefix("webauthn_state_1", b"user-1:")
        .expect("keyspace is ephemeral");
    assert_eq!(matched.len(), 2);

    // A Fjall-backed (non-ephemeral) keyspace name must fall through to
    // `None` rather than an empty result, so callers know to read Fjall
    // instead.
    assert!(sm.ephemeral_prefix("data", b"user-1:").is_none());
}

#[test]
fn drop_keyspace_reclaims_an_empty_ephemeral_partition() {
    let (sm, _td) = make_seeded_sm(0x09);
    seed(
        &sm,
        "webauthn_state_1",
        b"user-1:auth",
        b"payload",
        Metadata::ephemeral(),
    );
    // Drain it back out, mirroring what apply()'s Remove arm does.
    sm.ephemeral
        .get("webauthn_state_1")
        .expect("keyspace present")
        .remove(b"user-1:auth".as_slice());

    sm.drop_keyspace("webauthn_state_1")
        .expect("drop empty ephemeral keyspace");
    assert!(!sm.keyspace_exists("webauthn_state_1"));
}

#[test]
fn drop_keyspace_refuses_non_empty_ephemeral_partition() {
    let (sm, _td) = make_seeded_sm(0x09);
    seed(
        &sm,
        "webauthn_state_1",
        b"user-1:auth",
        b"payload",
        Metadata::ephemeral(),
    );

    let err = sm
        .drop_keyspace("webauthn_state_1")
        .expect_err("must refuse to drop a non-empty ephemeral keyspace");
    assert!(matches!(err, StoreError::Other(_)));
    assert!(sm.keyspace_exists("webauthn_state_1"));
    assert!(
        sm.ephemeral_get("webauthn_state_1", b"user-1:auth")
            .is_some(),
        "the failed drop must not have discarded the entry"
    );
}
