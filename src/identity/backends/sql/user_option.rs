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

use crate::db::entity::user_option;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::*;

mod list;

pub use list::list_by_user_id;

impl FromIterator<user_option::Model> for UserOptions {
    fn from_iter<I: IntoIterator<Item = user_option::Model>>(iter: I) -> Self {
        let mut user_opts: UserOptions = UserOptions::default();
        for opt in iter.into_iter() {
            match (opt.option_id.as_str(), opt.option_value) {
                ("1000", Some(val)) => {
                    user_opts.ignore_change_password_upon_first_use = val.parse().ok();
                }
                ("1001", Some(val)) => {
                    user_opts.ignore_password_expiry = val.parse().ok();
                }
                ("1002", Some(val)) => {
                    user_opts.ignore_lockout_failure_attempts = val.parse().ok();
                }
                ("1003", Some(val)) => {
                    user_opts.lock_password = val.parse().ok();
                }
                ("MFAR", Some(val)) => {
                    user_opts.multi_factor_auth_rules = serde_json::from_str(val.as_ref()).ok();
                }
                ("MFAE", Some(val)) => {
                    user_opts.multi_factor_auth_enabled = val.parse().ok();
                }
                _ => {}
            }
        }
        user_opts
    }
}

#[allow(unused)]
fn get_user_options_db_entries<U: AsRef<str>>(
    user_id: U,
    options: &UserOptions,
) -> Result<impl IntoIterator<Item = user_option::Model>, IdentityProviderError> {
    let mut res: Vec<user_option::Model> = Vec::new();
    if let Some(val) = &options.ignore_change_password_upon_first_use {
        res.push(user_option::Model {
            user_id: user_id.as_ref().to_string(),
            option_id: "1000".into(),
            option_value: Some(val.to_string()),
        });
    }
    if let Some(val) = &options.ignore_password_expiry {
        res.push(user_option::Model {
            user_id: user_id.as_ref().to_string(),
            option_id: "1001".into(),
            option_value: Some(val.to_string()),
        });
    }
    if let Some(val) = &options.ignore_lockout_failure_attempts {
        res.push(user_option::Model {
            user_id: user_id.as_ref().to_string(),
            option_id: "1002".into(),
            option_value: Some(val.to_string()),
        });
    }
    if let Some(val) = &options.lock_password {
        res.push(user_option::Model {
            user_id: user_id.as_ref().to_string(),
            option_id: "1003".into(),
            option_value: Some(val.to_string()),
        });
    }
    if let Some(val) = &options.multi_factor_auth_rules {
        res.push(user_option::Model {
            user_id: user_id.as_ref().to_string(),
            option_id: "MFAR".into(),
            option_value: Some(serde_json::to_string(val)?),
        });
    }
    if let Some(val) = &options.multi_factor_auth_enabled {
        res.push(user_option::Model {
            user_id: user_id.as_ref().to_string(),
            option_id: "MFAE".into(),
            option_value: Some(val.to_string()),
        });
    }
    Ok(res)
}

#[cfg(test)]
pub(super) mod tests {
    use crate::db::entity::user_option;
    use crate::identity::types::UserOptions;

    use super::*;

    impl Default for user_option::Model {
        fn default() -> Self {
            Self {
                user_id: "1".into(),
                option_id: "1000".into(),
                option_value: None,
            }
        }
    }

    pub fn get_user_options_mock(options: &UserOptions) -> Vec<user_option::Model> {
        get_user_options_db_entries("1", options)
            .unwrap()
            .into_iter()
            .collect()
    }
}
