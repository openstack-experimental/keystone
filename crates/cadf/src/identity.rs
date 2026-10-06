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
//! Identity of the service embedding the audit framework.
//!
//! Everything that would otherwise hard-code a service name is derived from
//! one [`ServiceIdentity`]: the HKDF domain label of the per-node signing key
//! and the prefix of the Prometheus metric names. Another OpenStack service
//! reuses the crate by declaring its own identity.

/// Name of the service writing audit records, e.g. `keystone`.
///
/// The name is restricted to `[a-z][a-z0-9_]*` so it is valid in both a
/// Prometheus metric name and the HKDF label. Declare it as a `const`: an
/// invalid name then fails the build instead of a scrape or a key derivation.
///
/// ```
/// use cadf::ServiceIdentity;
///
/// const SERVICE: ServiceIdentity = ServiceIdentity::new("keystone");
/// assert_eq!(
///     SERVICE.metric_name("spool_bytes"),
///     "keystone_audit_spool_bytes"
/// );
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceIdentity {
    /// The service's stable name, e.g. `"keystone"`.
    name: &'static str,
}

impl ServiceIdentity {
    /// HKDF `info` of the per-node signing key:
    /// `{name}-audit-hmac-v1:{node_id}`.
    pub(crate) fn kdf_info(&self, node_id: &str) -> String {
        format!("{}-audit-hmac-v1:{node_id}", self.name)
    }

    /// Prometheus metric name: `{name}_audit_{suffix}`.
    pub fn metric_name(&self, suffix: &str) -> String {
        format!("{}_audit_{suffix}", self.name)
    }

    /// The service name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Declare the identity of a service.
    ///
    /// # Panics
    ///
    /// Panics (at compile time when used in a `const`) if `name` is empty,
    /// does not start with a lowercase ASCII letter, or contains a character
    /// other than lowercase ASCII letters, digits and `_`.
    pub const fn new(name: &'static str) -> Self {
        let bytes = name.as_bytes();
        assert!(!bytes.is_empty(), "service name must not be empty");
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            let letter = b.is_ascii_lowercase();
            let ok = if i == 0 {
                letter
            } else {
                letter || b.is_ascii_digit() || b == b'_'
            };
            assert!(ok, "service name must match [a-z][a-z0-9_]*");
            i += 1;
        }
        Self { name }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_names() {
        let s = ServiceIdentity::new("nova");
        assert_eq!(s.name(), "nova");
        assert_eq!(s.kdf_info("n1"), "nova-audit-hmac-v1:n1");
        assert_eq!(s.metric_name("dropped_total"), "nova_audit_dropped_total");
    }

    #[test]
    #[should_panic(expected = "service name must match")]
    fn rejects_invalid_characters() {
        let _ = ServiceIdentity::new("my-service");
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn rejects_empty() {
        let _ = ServiceIdentity::new("");
    }
}
