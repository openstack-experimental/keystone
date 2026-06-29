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
//! Cross-language HMAC-SHA256 test vectors (ADR 0023 Phase 5.1).
//!
//! Reads `tests/audit/hmac_vectors.jsonl` from the workspace root and verifies
//! each vector against `AuditDispatcher::verify_hmac`. This guards the
//! JCS-canonical (RFC 8785) serialization and HMAC computation against
//! unintentional drift and provides reference values for SIEM implementors.
//!
//! **SIEM verification path (not in this file):**
//! 1. Parse received `CadfEvent` JSON.
//! 2. Remove the `signature` key.
//! 3. Re-serialize the remaining fields in JCS canonical form.
//! 4. Compute HMAC-SHA256 with the key for `hmac_key_version`.
//! 5. Compare with the `signature` value.
//!
//! To regenerate vectors after an intentional algorithm change, run:
//! `cargo test --test hmac_vectors write_hmac_vectors -- --ignored`

use std::sync::Arc;

use openstack_keystone_audit::{AuditDispatcher, CadfEvent};
use serde_json::Value;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[derive(serde::Deserialize)]
struct Vector {
    description: String,
    key_hex: String,
    expected_signature: String,
    event: Value,
}

fn vectors_path() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is crates/audit; walk up two levels to workspace root.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/audit/hmac_vectors.jsonl")
}

#[test]
fn verify_hmac_vectors() {
    let path = vectors_path();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let vectors: Vec<Vector> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("parse error: {e}\nline: {l}")))
        .collect();

    assert!(
        !vectors.is_empty(),
        "hmac_vectors.jsonl must contain at least one vector"
    );

    for v in &vectors {
        let key: Arc<[u8]> = Arc::from(hex_decode(&v.key_hex).as_slice());
        // Create a noop dispatcher with the vector's key — we only need
        // verify_hmac, which doesn't use the channel.
        let (dispatcher, _rx) = AuditDispatcher::new(
            "test-node",
            "00000000-0000-0000-0000-000000000001".to_string(),
            Arc::clone(&key),
            1,
        );

        // Deserialize the event from the vector's JSON.
        let event: CadfEvent = serde_json::from_value(v.event.clone()).unwrap_or_else(|e| {
            panic!("cannot deserialize CadfEvent for '{}': {e}", v.description)
        });

        assert_eq!(
            event.signature(),
            v.expected_signature,
            "signature field mismatch for vector '{}'",
            v.description
        );

        assert!(
            dispatcher.verify_hmac(&event, &key),
            "HMAC verification failed for vector '{}'",
            v.description
        );
    }

    println!("verified {} HMAC vectors", vectors.len());
}

/// Round-trip test: sign a deterministic payload, verify it, and confirm the
/// JCS-canonical form matches the expected structure without checking the exact
/// signature value (which would require the cross-language vectors above).
#[test]
fn hmac_roundtrip_deterministic_payload() {
    use openstack_keystone_audit::{CadfEventPayload, Initiator, Observer, Target};

    let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
    let (dispatcher, _rx) = AuditDispatcher::new(
        "test-node",
        "00000000-0000-0000-0000-000000000001".to_string(),
        Arc::clone(&key),
        1,
    );

    let payload = CadfEventPayload::new(
        "test-node:550e8400-e29b-41d4-a716-446655440000".to_string(),
        "1.0".to_string(),
        "default".to_string(),
        "req-00000000000000000000000000000002".to_string(),
        "2026-06-16T00:00:00+00:00".to_string(),
        "authenticate".to_string(),
        "success".to_string(),
        None,
        Initiator::new("unknown".to_string(), None, None, None),
        Target {
            id: "keystone".to_string(),
            type_uri: "service/security/keystone/auth".to_string(),
        },
        Observer {
            node_id: "test-node".to_string(),
            id: "service/security/keystone/test-node".to_string(),
        },
    );

    let event = payload.sign(&dispatcher);

    // Signature must verify with the original key.
    assert!(dispatcher.verify_hmac(&event, &key));

    // Signature must NOT verify with a different key.
    let wrong_key: Arc<[u8]> = Arc::from(b"wrong-key-32-bytes-000000000000".as_slice());
    assert!(!dispatcher.verify_hmac(&event, &wrong_key));

    // Serialized form must be valid JSON containing expected top-level fields.
    let json = serde_json::to_string(&event).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = parsed.as_object().unwrap();
    assert!(obj.contains_key("signature"));
    assert!(obj.contains_key("action"));
    assert!(obj.contains_key("outcome"));
    assert!(obj.contains_key("initiator"));
    assert!(obj.contains_key("target"));
    assert!(obj.contains_key("observer"));

    // Signature in the vector file must match the computed signature.
    let expected = "a45b198cabe787c13a635e7e25d13760cd5ee016fecf258a5e9a99cda1e25b4c";
    assert_eq!(
        event.signature(),
        expected,
        "signature diverged from cross-language vector; \
         if you changed the signing algorithm, regenerate hmac_vectors.jsonl"
    );
}

// Tamper-detection test lives in `crates/audit/src/types.rs` as a unit test,
// where it has pub(crate) access to `CadfEvent::signature` to simulate tampering.
