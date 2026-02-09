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

/// Token provider.
#[derive(Debug, Deserialize, Clone)]
pub struct TokenProvider {
    /// Token provider driver.
    #[serde(default)]
    pub provider: TokenProviderDriver,
    /// The amount of time that a token should remain valid (in seconds).
    /// Drastically reducing this value may break "long-running" operations
    /// that involve multiple services to coordinate together, and will
    /// force users to authenticate with keystone more frequently. Drastically
    /// increasing this value will increase the number of tokens that will be
    /// simultaneously valid. Keystone tokens are also bearer tokens, so a
    /// shorter duration will also reduce the potential security impact of a
    /// compromised token.
    #[serde(default = "default_token_expiration")]
    pub expiration: usize,
}

fn default_token_expiration() -> usize {
    3600
}

impl Default for TokenProvider {
    fn default() -> Self {
        Self {
            provider: TokenProviderDriver::Fernet,
            expiration: default_token_expiration(),
        }
    }
}

/// Token provider driver.
#[derive(Debug, Default, Deserialize, Clone)]
pub enum TokenProviderDriver {
    /// Fernet.
    #[default]
    #[serde(rename = "fernet")]
    Fernet,
}
