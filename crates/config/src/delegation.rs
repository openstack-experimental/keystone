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
//! # Service delegation configuration (ADR 0036)
use serde::Deserialize;

use crate::pagination::ListLimitConfig;

/// `[delegation]`: service grants (ADR 0036 §4, §5, §8).
#[derive(Debug, Deserialize, Clone)]
pub struct DelegationProvider {
    /// Deployment-wide backstop on live service grants per project, on top
    /// of each client's own `max_grants_per_project`.
    #[serde(default = "default_max_grants_per_project")]
    pub max_grants_per_project: u64,

    /// Seconds between two `last_redeemed_at` writes of one grant; a
    /// redemption inside the interval does not touch storage.
    #[serde(default = "default_last_redeemed_update_interval")]
    pub last_redeemed_update_interval: u64,

    /// Seconds an expired or disabled-as-expired grant is kept before the
    /// janitor deletes it.
    #[serde(default = "default_expired_grant_retention")]
    pub expired_grant_retention: u64,

    /// Seconds between two runs of the grant janitor.
    #[serde(default = "default_janitor_interval")]
    pub janitor_interval: u64,

    /// `GET /v4/service-grants` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,
}

fn default_max_grants_per_project() -> u64 {
    10_000
}

fn default_last_redeemed_update_interval() -> u64 {
    3600
}

fn default_expired_grant_retention() -> u64 {
    30 * 24 * 3600
}

fn default_janitor_interval() -> u64 {
    3600
}

impl Default for DelegationProvider {
    fn default() -> Self {
        Self {
            max_grants_per_project: default_max_grants_per_project(),
            last_redeemed_update_interval: default_last_redeemed_update_interval(),
            expired_grant_retention: default_expired_grant_retention(),
            janitor_interval: default_janitor_interval(),
            list_limit: ListLimitConfig::default(),
        }
    }
}
