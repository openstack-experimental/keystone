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
use crate::db::entity::{local_user as db_local_user, password as db_password, user as db_user};
use crate::identity::types::*;

mod create;
mod get;
mod load;
mod set;

pub use create::create;
pub use load::load_local_user_with_passwords;
pub use load::load_local_users_passwords;
pub use set::reset_failed_auth;

pub fn get_local_user_builder<P: IntoIterator<Item = db_password::Model>>(
    conf: &Config,
    user: &db_user::Model,
    data: db_local_user::Model,
    passwords: Option<P>,
    opts: UserOptions,
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

#[cfg(test)]
pub(super) mod tests {
    use chrono::{Local, Utc};

    use crate::db::entity::{local_user as db_local_user, password as db_password};

    impl Default for db_local_user::Model {
        fn default() -> Self {
            Self {
                id: 1,
                user_id: "user_id".into(),
                domain_id: "foo_domain".into(),
                name: "foo_domain".into(),
                failed_auth_count: Some(0),
                failed_auth_at: Some(Utc::now().naive_utc()),
            }
        }
    }

    pub fn get_local_user_with_password_mock<U: AsRef<str>>(
        user_id: U,
        cnt_password: usize,
    ) -> Vec<(db_local_user::Model, db_password::Model)> {
        let lu = db_local_user::Model {
            user_id: user_id.as_ref().into(),
            domain_id: "foo_domain".into(),
            name: "Apple Cake".to_owned(),
            ..Default::default()
        };
        let mut passwords: Vec<db_password::Model> = Vec::new();
        for i in 0..cnt_password {
            passwords.push(db_password::Model {
                id: i as i32,
                local_user_id: 1,
                expires_at: None,
                self_service: false,
                password_hash: None,
                created_at: Local::now().naive_utc(),
                created_at_int: 12345,
                expires_at_int: None,
            });
        }
        passwords
            .into_iter()
            .map(|x| (lu.clone(), x.clone()))
            .collect()
    }
}
