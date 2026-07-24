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
//! # Credential provider configuration (ADR 0019)
use serde::Deserialize;
use std::path::PathBuf;

use crate::common::default_sql_driver;
use crate::pagination::ListLimitConfig;

/// Credential provider.
///
/// The Fernet key repository used here is separate from `[fernet_tokens]`
/// (ADR 0019 §4) and is hard-capped at 3 active keys (`MAX_ACTIVE_KEYS = 3`,
/// matching the Python Keystone constant); unlike token Fernet keys this is
/// intentionally not configurable.
#[derive(Debug, Deserialize, Clone)]
pub struct CredentialProvider {
    /// Credential provider driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// Path to the credential Fernet keys. Must be a directory distinct from
    /// `[fernet_tokens] key_repository`.
    #[serde(default = "default_credential_key_repository")]
    pub key_repository: PathBuf,

    /// Allow starting (and encrypting/decrypting with) the well-known Null
    /// Key (`base64.urlsafe_b64encode(b'\x00' * 32)`). This exists solely as
    /// a transient migration aid; it must be `false` in any real deployment.
    /// Defaults to `false` (refuse to start if a key file decodes to the
    /// Null Key).
    #[serde(default)]
    pub insecure_allow_null_key: bool,

    /// `GET /v3/credentials` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,
}

fn default_credential_key_repository() -> PathBuf {
    PathBuf::from("/etc/keystone/credential-keys/")
}

impl Default for CredentialProvider {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
            key_repository: default_credential_key_repository(),
            insecure_allow_null_key: false,
            list_limit: ListLimitConfig::default(),
        }
    }
}
