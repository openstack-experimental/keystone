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
//! # API Key (SCIM ingress) provider configuration
//!
//! See ADR 0021 (Stateless API-Key Ingress & Ephemeral Security Contexts for
//! SCIM).
use ipnet::IpNet;
use serde::Deserialize;
use validator::Validate;

use crate::common::{ProxyHeader, csv_ipnet, default_raft_driver};

/// API Key (SCIM ingress) provider configuration.
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct ApiKeyProvider {
    /// Argon2id memory cost, in KiB, required of any stored PHC hash. Values
    /// below this floor trigger a lazy re-hash on next successful
    /// verification (ADR 0021 §6.B, Invariant 8).
    #[serde(default = "default_argon2_memory_kib")]
    #[validate(range(min = 1))]
    pub argon2_memory_kib: u32,

    /// Argon2id time cost (iterations) required of any stored PHC hash.
    #[serde(default = "default_argon2_time_cost")]
    #[validate(range(min = 1))]
    pub argon2_time_cost: u32,

    /// Argon2id parallelism (lanes) required of any stored PHC hash.
    #[serde(default = "default_argon2_parallelism")]
    #[validate(range(min = 1))]
    pub argon2_parallelism: u32,

    /// API Key backend.
    #[serde(default = "default_raft_driver")]
    pub driver: String,

    /// Maximum number of days an API Key may go unused (per `last_used_at`)
    /// before the janitor disables it (PCI-DSS inactivity threshold).
    #[serde(default = "default_janitor_inactive_days")]
    #[validate(range(min = 1))]
    pub janitor_inactive_days: u32,

    /// Additional days beyond `janitor_inactive_days` before disablement, to
    /// absorb bounded drift from asynchronous `last_used_at` writes (ADR
    /// 0021 §6.F).
    #[serde(default = "default_janitor_grace_days")]
    pub janitor_grace_days: u32,

    /// Number of days a revoked key's tombstone is retained for audit before
    /// the janitor physically purges it from storage (ADR 0021 §6.F).
    #[serde(default = "default_janitor_tombstone_retention_days")]
    #[validate(range(min = 1))]
    pub janitor_tombstone_retention_days: u32,

    /// CIDR blocks of reverse proxies trusted to append entries to the
    /// configured [`trusted_header`](Self::trusted_header). Used to compute
    /// the effective client IP via the rightmost-non-trusted algorithm (ADR
    /// 0021 §3 Step 2, §6.E,
    /// Invariant 4). Parsed into [`IpNet`] networks at configuration-load time
    /// (not on every request); a malformed CIDR fails configuration loading.
    #[serde(deserialize_with = "csv_ipnet", default)]
    pub trusted_proxies: Vec<IpNet>,

    /// The one forwarding header trusted proxies are required to sanitize.
    /// `x_forwarded_for` is the backward-compatible default. RFC 7239
    /// `forwarded` must be opted into explicitly.
    #[serde(default)]
    pub trusted_header: ProxyHeader,

    /// Maximum burst of SCIM ingress authentication attempts accepted
    /// instantaneously, per rate-limit key (`lookup_hash`, or source IP when
    /// the token fails the format check), before throttling kicks in (ADR
    /// 0021 §6.A).
    #[serde(default = "default_rate_limit_burst_size")]
    #[validate(range(min = 1))]
    pub rate_limit_burst_size: u32,

    /// Sustained SCIM ingress authentication attempts allowed per minute,
    /// per rate-limit key, once the burst allowance is exhausted.
    #[serde(default = "default_rate_limit_replenish_per_minute")]
    #[validate(range(min = 1))]
    pub rate_limit_replenish_per_minute: u32,
}

fn default_argon2_memory_kib() -> u32 {
    65536
}

fn default_argon2_time_cost() -> u32 {
    3
}

fn default_argon2_parallelism() -> u32 {
    4
}

fn default_janitor_inactive_days() -> u32 {
    90
}

fn default_janitor_grace_days() -> u32 {
    7
}

fn default_janitor_tombstone_retention_days() -> u32 {
    365
}

fn default_rate_limit_burst_size() -> u32 {
    10
}

fn default_rate_limit_replenish_per_minute() -> u32 {
    60
}

impl Default for ApiKeyProvider {
    fn default() -> Self {
        Self {
            driver: default_raft_driver(),
            argon2_memory_kib: default_argon2_memory_kib(),
            argon2_time_cost: default_argon2_time_cost(),
            argon2_parallelism: default_argon2_parallelism(),
            janitor_inactive_days: default_janitor_inactive_days(),
            janitor_grace_days: default_janitor_grace_days(),
            janitor_tombstone_retention_days: default_janitor_tombstone_retention_days(),
            trusted_proxies: Vec::new(),
            trusted_header: ProxyHeader::default(),
            rate_limit_burst_size: default_rate_limit_burst_size(),
            rate_limit_replenish_per_minute: default_rate_limit_replenish_per_minute(),
        }
    }
}
