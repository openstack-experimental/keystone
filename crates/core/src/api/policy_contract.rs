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
//! Gate B2 (security review V3a, issue #978): shared assertions for the
//! handler -> policy input contract.
//!
//! `opa test policy` (Gate A) proves the Rego is right on *hand-authored*
//! input. It says nothing about whether a handler actually builds that
//! input correctly -- the wrong `policy_name`, a mis-keyed `target`, a
//! `target`/`existing` swap on update, or a leaked secret field all produce
//! a well-formed request to a correct policy that decides on the wrong
//! document. These helpers are the uniform, non-opt-in assertion set applied
//! to [`super::tests::CapturingPolicy`]'s recorded calls.

use serde_json::Value;

/// Field names that must never appear anywhere in a `target`/`existing`
/// policy-input document (`security.md` I7, generalized). Decrypted secret
/// material (a credential's `blob`, a user's `password`, an OAuth2 client's
/// `client_secret`, ...) has no `.rego` rule that reads it, so its presence
/// here would only ever feed an OPA decision log or a future careless rule.
const SECRET_FIELD_NAMES: &[&str] = &[
    "access_token",
    "blob",
    "client_secret",
    "encrypted_blob",
    "key_hash",
    "password",
    "refresh_token",
    "secret",
    "seed",
    "totp_seed",
    "token",
];

/// Assert that `value` is a JSON object whose top-level keys are *exactly*
/// `expected` (order-independent). This is the mechanical form of ADR 0002's
/// `{"target": {"<resource>": obj}}` contract: a mis-keyed resource name
/// makes every `input.target.<resource>.*` lookup `undefined` at runtime,
/// which an `undefined`-driven Rego rule can silently treat as allow.
///
/// Some endpoints legitimately carry more than one top-level key (e.g. the
/// OS-EC2 legacy API's `{"user_id": ..., "credential": ...}`, documented in
/// `policy/os_ec2/*.rego`) -- pass the endpoint's full, actual key set, not
/// just the resource name, for those.
///
/// # Panics
/// Panics with a descriptive message if `value` is not an object, or its key
/// set doesn't match `expected`.
pub fn assert_object_keys(value: &Value, expected: &[&str]) {
    let obj = value
        .as_object()
        .unwrap_or_else(|| panic!("expected a JSON object, got {value:?}"));
    let mut actual: Vec<&str> = obj.keys().map(String::as_str).collect();
    actual.sort_unstable();
    let mut expected: Vec<&str> = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "policy-input object has keys {actual:?}, expected {expected:?} (value: {value})"
    );
}

/// Assert that `value` (and everything nested under it) carries no field
/// named in [`SECRET_FIELD_NAMES`]. Run over both `target` and `existing`.
///
/// # Panics
/// Panics naming the first offending field path found.
pub fn assert_no_secrets(value: &Value) {
    if let Some(path) = find_secret_field(value, "$") {
        panic!("policy input leaks secret field at {path}: {value}");
    }
}

fn find_secret_field(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            for (key, v) in map {
                if SECRET_FIELD_NAMES
                    .iter()
                    .any(|denied| denied.eq_ignore_ascii_case(key))
                {
                    return Some(format!("{path}.{key}"));
                }
                if let Some(found) = find_secret_field(v, &format!("{path}.{key}")) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, v)| find_secret_field(v, &format!("{path}[{i}]"))),
        _ => None,
    }
}

/// Assert `existing` matches the expected create/show/update/delete/list
/// slotting (ADR 0002): create/list pass `None`; show/delete/update pass
/// `Some(..)` (the codebase's actual, `opa test`-covered convention keys the
/// stored object under `existing` for show/delete too, not only update --
/// see e.g. `policy/credential/show.rego`'s documented `input.existing`).
///
/// # Panics
/// Panics if presence doesn't match `expected_present`.
pub fn assert_existing_presence(existing: &Option<Value>, expected_present: bool) {
    assert_eq!(
        existing.is_some(),
        expected_present,
        "existing presence was {}, expected {}",
        existing.is_some(),
        expected_present
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_assert_object_keys_ok() {
        assert_object_keys(&json!({"credential": {}}), &["credential"]);
        assert_object_keys(
            &json!({"user_id": "u", "credential": null}),
            &["credential", "user_id"],
        );
    }

    #[test]
    #[should_panic(expected = "expected [\"user_id\"]")]
    fn test_assert_object_keys_wrong_key() {
        assert_object_keys(&json!({"credentials": {}}), &["user_id"]);
    }

    #[test]
    #[should_panic(expected = "expected a JSON object")]
    fn test_assert_object_keys_not_object() {
        assert_object_keys(&Value::Null, &["credential"]);
    }

    #[test]
    fn test_assert_no_secrets_ok() {
        assert_no_secrets(&json!({"credential": {"id": "1", "type": "totp"}}));
    }

    #[test]
    #[should_panic(expected = "leaks secret field at $.credential.blob")]
    fn test_assert_no_secrets_catches_blob() {
        assert_no_secrets(&json!({"credential": {"id": "1", "blob": "{\"seed\":\"AAAA\"}"}}));
    }

    #[test]
    #[should_panic(expected = "leaks secret field at $.user.password")]
    fn test_assert_no_secrets_catches_nested() {
        assert_no_secrets(&json!({"user": {"name": "a", "password": "hunter2"}}));
    }

    #[test]
    fn test_assert_existing_presence() {
        assert_existing_presence(&None, false);
        assert_existing_presence(&Some(json!({})), true);
    }
}
