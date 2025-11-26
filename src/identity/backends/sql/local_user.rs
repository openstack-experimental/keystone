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

use chrono::{DateTime, Days, Utc};

use super::user;
use crate::config::Config;
use crate::db::entity::{
    local_user as db_local_user, password as db_password, user as db_user,
    user_option as db_user_option,
};
use crate::identity::types::*;

mod create;
mod get;
mod load;

pub use create::create;
pub use load::load_local_user_with_passwords;
pub use load::load_local_users_passwords;

pub fn get_local_user_builder<
    O: IntoIterator<Item = db_user_option::Model>,
    P: IntoIterator<Item = db_password::Model>,
>(
    conf: &Config,
    user: &db_user::Model,
    data: db_local_user::Model,
    passwords: Option<P>,
    opts: O,
) -> UserResponseBuilder {
    let mut user_builder: UserResponseBuilder = user::get_user_builder(user, opts);
    user_builder.name(data.name.clone());
    if let Some(password_expires_days) = conf.security_compliance.password_expires_days
        && let Some(pass) = passwords
        && let (Some(current_password), Some(options)) =
            (pass.into_iter().next(), user_builder.get_options())
        && let Some(false) = options.ignore_password_expiry.or(Some(false))
        && let Some(dt) = DateTime::from_timestamp_micros(current_password.created_at_int)
            .unwrap_or(DateTime::from_naive_utc_and_offset(
                current_password.created_at,
                Utc,
            ))
            .checked_add_days(Days::new(password_expires_days))
    {
        user_builder.password_expires_at(dt);
    }
    user_builder
}
