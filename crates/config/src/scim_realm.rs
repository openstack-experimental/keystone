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
use crate::pagination::ListLimitConfig;

/// SCIM realm provider (ADR 0024).
#[derive(Debug, Deserialize, Clone)]
pub struct ScimRealmProvider {
    /// SCIM realm provider driver.
    #[serde(default = "default_raft_driver")]
    pub driver: String,

    /// `GET /v4/scim-realms` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,
}

impl Default for ScimRealmProvider {
    fn default() -> Self {
        Self {
            driver: default_raft_driver(),
            list_limit: ListLimitConfig::default(),
        }
    }
}
