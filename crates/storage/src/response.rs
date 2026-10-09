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
//! # Raft application response.
//!
//! [`ZeroizingResponse`] is the `R` of the crate's `TypeConfig`: what the
//! state machine returns from `apply()`. It carries decrypted plaintext, so
//! it is zeroized on drop, redacted in `Debug`, and convertible to and from
//! the `pb::api::Response` wire type.

use crate::pb;

/// Application response returned by the state machine on `apply()` (ADR
/// 0016-v2 §8: `RaftResponse` — "Ephemeral plaintext response, transmitted
/// only over mTLS. Zeroized by the sender immediately after gRPC send.").
///
/// `value` holds decrypted plaintext for reads served through the Raft
/// write path (e.g. `CreateIfAbsent` echoing back the stored value); it is
/// wrapped in `Zeroizing` so the buffer is scrubbed as soon as the last
/// clone/owner drops, rather than lingering in freed heap memory until
/// reused. This narrows, but does not eliminate, the exposure window: gRPC
/// implementations (tonic/prost) may still buffer or copy bytes internally
/// during transmission, which this wrapper cannot reach — the compensating
/// controls for that residual risk are `RLIMIT_CORE = 0` and
/// `PR_SET_DUMPABLE = 0`, enforced at startup (see `preflight.rs`).
#[derive(Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ZeroizingResponse {
    /// Decrypted plaintext value, when the operation returns one.
    #[serde(with = "zeroizing_bytes_serde")]
    pub value: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// Violations detected during the operation (e.g. CAS conflicts).
    pub violations: Vec<pb::api::response::Violation>,
}

/// Redacts `value` instead of deriving `Debug`, so an accidental `{:?}` in a
/// log line or error message never prints plaintext. `openraft`'s own
/// testing harness requires `C::R: Debug`, so this can't simply be omitted.
impl std::fmt::Debug for ZeroizingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroizingResponse")
            .field(
                "value",
                &self
                    .value
                    .as_ref()
                    .map(|v| format!("<redacted {} bytes>", v.len())),
            )
            .field("violations", &self.violations)
            .finish()
    }
}

/// The `zeroize` crate does not implement `serde::{Serialize, Deserialize}`
/// for `Zeroizing<T>`, so this shim (de)serializes the value as a plain
/// `Option<Vec<u8>>` and wraps/unwraps `Zeroizing` at the boundary. Note
/// this shim is only exercised in the (rare) `AppendEntries`/snapshot
/// replay path — normal client responses never leave the local process.
mod zeroizing_bytes_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(
        value: &Option<Zeroizing<Vec<u8>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.as_deref().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Zeroizing<Vec<u8>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        Ok(v.map(Zeroizing::new))
    }
}

impl From<ZeroizingResponse> for pb::api::Response {
    fn from(r: ZeroizingResponse) -> Self {
        Self {
            value: r.value.map(|v| v.to_vec()),
            violations: r.violations,
        }
    }
}

impl From<pb::api::Response> for ZeroizingResponse {
    fn from(r: pb::api::Response) -> Self {
        Self {
            value: r.value.map(zeroize::Zeroizing::new),
            violations: r.violations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ZeroizingResponse` must round-trip losslessly through the
    /// `pb::api::Response` wire type in both directions (ADR 0016-v2 §8).
    #[test]
    fn zeroizing_response_round_trips_through_wire_type() {
        let original = ZeroizingResponse {
            value: Some(zeroize::Zeroizing::new(b"top secret".to_vec())),
            violations: vec![pb::api::response::Violation {
                r#type: "CONFLICT".to_string(),
                subject: "some-key".to_string(),
                description: "revision mismatch".to_string(),
            }],
        };

        let wire: pb::api::Response = original.clone().into();
        assert_eq!(wire.value.as_deref(), Some(b"top secret".as_slice()));
        assert_eq!(wire.violations.len(), 1);

        let back: ZeroizingResponse = wire.into();
        assert_eq!(back.value.as_deref(), original.value.as_deref());
        assert_eq!(back.violations, original.violations);
    }

    /// `Debug` must redact the plaintext value rather than deriving it, so
    /// an accidental `{:?}` never leaks the response payload (ADR 0016-v2
    /// §9 spirit — don't format secrets).
    #[test]
    fn zeroizing_response_debug_redacts_value() {
        let resp = ZeroizingResponse {
            value: Some(zeroize::Zeroizing::new(b"top secret".to_vec())),
            violations: vec![],
        };
        let debug_str = format!("{resp:?}");
        assert!(!debug_str.contains("top secret"));
        assert!(debug_str.contains("redacted"));
    }
}
