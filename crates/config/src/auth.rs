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
use validator::Validate;

use crate::common::csv;

/// Authentication configuration.
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct AuthProvider {
    /// Authentication methods to be enabled and used for token validation.
    #[serde(deserialize_with = "csv")]
    pub methods: Vec<String>,

    /// Maximum number of live entries of the TOTP passcode replay cache
    /// (ADR 0044 §2) of the `local` store. When it is full new passcodes are
    /// rejected rather than evicting older entries.
    #[serde(default = "default_totp_replay_cache_max_entries")]
    #[validate(range(min = 1))]
    pub totp_replay_cache_max_entries: u32,

    /// Maximum number of live TOTP replay entries held for one user.
    #[serde(default = "default_totp_replay_cache_max_entries_per_user")]
    #[validate(range(min = 1))]
    pub totp_replay_cache_max_entries_per_user: u32,
}

fn default_totp_replay_cache_max_entries() -> u32 {
    100_000
}

fn default_totp_replay_cache_max_entries_per_user() -> u32 {
    32
}

impl Default for AuthProvider {
    fn default() -> Self {
        Self {
            methods: Vec::new(),
            totp_replay_cache_max_entries: default_totp_replay_cache_max_entries(),
            totp_replay_cache_max_entries_per_user: default_totp_replay_cache_max_entries_per_user(
            ),
        }
    }
}

impl AuthProvider {
    /// Check that the per-user TOTP replay bound does not exceed the total
    /// (ADR 0044 §2).
    pub fn validate_totp_replay(&self) -> Result<(), String> {
        if self.totp_replay_cache_max_entries_per_user > self.totp_replay_cache_max_entries {
            return Err(
                "[auth] totp_replay_cache_max_entries_per_user must not exceed \
                 totp_replay_cache_max_entries"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_replay_bounds() {
        assert!(AuthProvider::default().validate_totp_replay().is_ok());
        assert!(AuthProvider::default().validate().is_ok());
        let bad = AuthProvider {
            totp_replay_cache_max_entries: 10,
            totp_replay_cache_max_entries_per_user: 11,
            ..Default::default()
        };
        assert!(bad.validate_totp_replay().is_err());
        let zero = AuthProvider {
            totp_replay_cache_max_entries: 0,
            ..Default::default()
        };
        assert!(zero.validate().is_err());
    }
}
