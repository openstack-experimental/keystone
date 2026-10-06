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
//! # Keystone configuration
//!
//! Parsing of the Keystone configuration file implementation.
use serde::Deserialize;

pub use oslo_config::{
    TlsConfiguration, TlsConfigurationBuilder, TlsConfigurationBuilderError, csv, csv_ipnet,
    default_true, option_u32_from_str_or_int, optional_timedelta_from_seconds,
};

/// Forwarding header an operator asserts its trusted proxies sanitize.
///
/// Exactly one header is selected for each ingress trust boundary. Trusting
/// both implicitly would allow a proxy that only owns `X-Forwarded-For` to
/// pass through a client-forged RFC 7239 `Forwarded` header (or vice versa).
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyHeader {
    /// The de-facto standard header used by the existing ingress paths.
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded`; opt in only when every trusted proxy sanitizes it.
    Forwarded,
}

impl ProxyHeader {
    /// Lowercase HTTP field name used by `HeaderMap` and normalized maps.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XForwardedFor => "x-forwarded-for",
            Self::Forwarded => "forwarded",
        }
    }
}

pub fn default_sql_driver() -> String {
    "sql".into()
}

pub fn default_raft_driver() -> String {
    "raft".into()
}

/// Server interface type.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Interface {
    Admin,
    Internal,
    Public,
    /// The dedicated health/metrics listener (`interface_metrics`). Only
    /// ever attached to that listener's own router — see
    /// `crates/keystone/src/server/http_metrics.rs` and
    /// `docs/superpowers/specs/2026-07-31-http-status-metrics-design.md`
    /// for why this is safe alongside the security-relevant use of this
    /// enum in `crates/core/src/api/auth.rs`.
    Metrics,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_is_hashable_and_copy() {
        use std::collections::HashSet;

        let a = Interface::Public;
        let b = a; // requires Copy
        let mut set: HashSet<Interface> = HashSet::new(); // requires Eq + Hash
        set.insert(a);
        set.insert(b);
        set.insert(Interface::Metrics);
        assert_eq!(set.len(), 2);
    }
}
