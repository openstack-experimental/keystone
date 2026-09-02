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
use serde::Deserialize;
use validator::Validate;

use crate::common::default_raft_driver;
use crate::pagination::ListLimitConfig;

/// SCIM realm provider (ADR 0024).
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct ScimRealmProvider {
    /// SCIM realm provider driver.
    #[serde(default = "default_raft_driver")]
    pub driver: String,

    /// `GET /v4/scim-realms` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,

    /// Maximum burst of SCIM resource writes (`POST`/`PUT`/`PATCH`/`DELETE`
    /// on `/SCIM/v2/{domain_id}/Users|Groups`) accepted instantaneously, per
    /// rate-limit key (the realm's `provider_id`), before throttling kicks
    /// in (ADR 0024 §11).
    #[serde(default = "default_write_rate_limit_burst_size")]
    #[validate(range(min = 1))]
    pub write_rate_limit_burst_size: u32,

    /// Sustained SCIM resource writes allowed per minute, per realm
    /// `provider_id`, once the burst allowance is exhausted
    /// (`scim_realm_write_rate_limit`, ADR 0024 §11). A second, independent
    /// tier from the per-`lookup_hash` authentication limiter (ADR 0021
    /// §6.A) that already covers every SCIM ingress request -- this one
    /// bounds bulk provisioning bursts from a single compromised or
    /// misconfigured realm specifically.
    #[serde(default = "default_write_rate_limit_replenish_per_minute")]
    #[validate(range(min = 1))]
    pub write_rate_limit_replenish_per_minute: u32,
}

fn default_write_rate_limit_burst_size() -> u32 {
    50
}

fn default_write_rate_limit_replenish_per_minute() -> u32 {
    500
}

impl Default for ScimRealmProvider {
    fn default() -> Self {
        Self {
            driver: default_raft_driver(),
            list_limit: ListLimitConfig::default(),
            write_rate_limit_burst_size: default_write_rate_limit_burst_size(),
            write_rate_limit_replenish_per_minute: default_write_rate_limit_replenish_per_minute(),
        }
    }
}
