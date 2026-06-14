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
use secrecy::SecretString;
use serde::Deserialize;

use crate::common::default_raft_driver;

/// Mapping provider.
#[derive(Debug, Deserialize, Clone)]
pub struct MappingProvider {
    /// Mapping provider driver.
    #[serde(default = "default_raft_driver")]
    pub driver: String,

    /// 256-bit HMAC key (hex-encoded) for deriving deterministic virtual user
    /// IDs via `HMAC-SHA256(salt, workload_id || provider_id)`.
    /// If not configured, `authenticate_by_mapping` will fail with
    /// `HmacDerivationFailed`.
    /// Secrecy 0.10 intentionally does NOT implement `Serialize` for
    /// `SecretString` to prevent secret leakage via serialization. This
    /// field can only be deserialized from config, which is the correct
    /// security posture.
    #[serde(default)]
    pub cluster_salt: Option<SecretString>,
}

impl Default for MappingProvider {
    fn default() -> Self {
        Self {
            driver: default_raft_driver(),
            cluster_salt: None,
        }
    }
}
