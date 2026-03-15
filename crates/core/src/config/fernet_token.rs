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
use std::path::PathBuf;

/// Fernet token provider.
#[derive(Debug, Deserialize, Clone)]
pub struct FernetTokenProvider {
    /// Path to the fernet keys.
    #[serde(default = "default_fernet_key_repository")]
    pub key_repository: PathBuf,
    /// Maximal number of fernet keys to keep as active.
    #[serde(default = "default_fernet_max_active_keys")]
    pub max_active_keys: usize,
}

fn default_fernet_key_repository() -> PathBuf {
    PathBuf::from("/etc/keystone/fernet-keys/")
}

fn default_fernet_max_active_keys() -> usize {
    3
}

impl Default for FernetTokenProvider {
    fn default() -> Self {
        Self {
            key_repository: default_fernet_key_repository(),
            max_active_keys: default_fernet_max_active_keys(),
        }
    }
}
