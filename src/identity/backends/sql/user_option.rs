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
