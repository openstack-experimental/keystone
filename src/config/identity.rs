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
use std::collections::HashMap;

use crate::config::common::default_sql_driver;

/// Identity provider.
#[derive(Debug, Deserialize, Clone)]
pub struct IdentityProvider {
    /// Caching.
    #[serde(default)]
    pub caching: bool,

    /// Identity provider driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// Maximal password length.
    #[serde(default = "default_max_password_length")]
    pub max_password_length: usize,

    /// Default password hashing algorithm.
    #[serde(default)]
    pub password_hashing_algorithm: PasswordHashingAlgo,

    /// Default number of password hashing rounds.
    pub password_hash_rounds: Option<usize>,

    /// User options id to name mapping.
    #[serde(default = "default_user_options_mapping")]
    pub user_options_id_name_mapping: HashMap<String, String>,
}

impl Default for IdentityProvider {
    fn default() -> Self {
        Self {
            caching: false,
            driver: default_sql_driver(),
            max_password_length: default_max_password_length(),
            password_hashing_algorithm: PasswordHashingAlgo::Bcrypt,
            password_hash_rounds: None,
            user_options_id_name_mapping: default_user_options_mapping(),
        }
    }
}

/// Password hashing algorithm.
#[derive(Debug, Default, Deserialize, Clone)]
pub enum PasswordHashingAlgo {
    /// Bcrypt.
    #[default]
    Bcrypt,
    #[cfg(test)]
    /// None. Should not be used outside of testing where expected value is
    /// necessary.
    None,
}

fn default_user_options_mapping() -> HashMap<String, String> {
    HashMap::from([
        (
            "1000".into(),
            "ignore_change_password_upon_first_use".into(),
        ),
        ("1001".into(), "ignore_password_expiry".into()),
        ("1002".into(), "ignore_lockout_failure_attempts".into()),
        ("1003".into(), "lock_password".into()),
    ])
}

fn default_max_password_length() -> usize {
    4096
}
