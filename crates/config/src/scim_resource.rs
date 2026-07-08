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

use crate::common::default_raft_driver;

/// SCIM resource ownership index provider (ADR 0024 §3.A).
#[derive(Debug, Deserialize, Clone)]
pub struct ScimResourceProvider {
    /// SCIM resource ownership index provider driver.
    #[serde(default = "default_raft_driver")]
    pub driver: String,

    /// Number of days a tombstoned (`deprovisioned_at` set) SCIM `User`/
    /// `Group` is retained before the janitor permanently purges it (ADR
    /// 0024 §6.C). Deployer-controlled specifically so regulated
    /// deployments can set it far below the 365-day default, including
    /// near-zero, to satisfy a right-to-erasure request without waiting a
    /// full year.
    #[serde(default = "default_janitor_deprovisioned_retention_days")]
    pub janitor_deprovisioned_retention_days: u32,
}

fn default_janitor_deprovisioned_retention_days() -> u32 {
    365
}

impl Default for ScimResourceProvider {
    fn default() -> Self {
        Self {
            driver: default_raft_driver(),
            janitor_deprovisioned_retention_days: default_janitor_deprovisioned_retention_days(),
        }
    }
}
