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

use crate::config::common::default_sql_driver;

/// Trust provider.
#[derive(Debug, Deserialize, Clone)]
pub struct TrustProvider {
    /// Allows authorization to be redelegated from one user to another,
    /// effectively chaining trusts together. When disabled, the
    /// `remaining_uses` attribute of a trust is constrained to be zero.
    #[serde(default)]
    pub allow_redelegation: bool,
    /// Trust provider driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,
    /// Maximum number of times that authorization can be redelegated from one
    /// user to another in a chain of trusts. This number may be reduced
    /// further for a specific trust.
    #[serde(default = "default_max_redelegation_count")]
    pub max_redelegation_count: usize,
}

fn default_max_redelegation_count() -> usize {
    3
}

impl Default for TrustProvider {
    fn default() -> Self {
        Self {
            allow_redelegation: false,
            driver: default_sql_driver(),
            max_redelegation_count: default_max_redelegation_count(),
        }
    }
}
