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

use serde_json::Value;
use tracing::error;

use crate::db::entity::{user as db_user, user_option as db_user_option};
use crate::identity::types::*;

mod create;
mod delete;
mod get;
mod list;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub(super) use get::get_main_entry;
pub use list::list;

pub fn get_user_builder<O: IntoIterator<Item = db_user_option::Model>>(
    user: &db_user::Model,
    opts: O,
) -> UserResponseBuilder {
    let mut user_builder: UserResponseBuilder = UserResponseBuilder::default();
    user_builder.id(user.id.clone());
    user_builder.domain_id(user.domain_id.clone());
    // TODO: default enabled logic
    user_builder.enabled(user.enabled.unwrap_or(false));
    if let Some(extra) = &user.extra {
        user_builder.extra(
            serde_json::from_str::<Value>(extra)
                .inspect_err(|e| error!("failed to deserialize user extra: {e}"))
                .unwrap_or_default(),
        );
    }

    user_builder.options(UserOptions::from_iter(opts));

    user_builder
}

#[cfg(test)]
mod tests {
    use chrono::Local;

    use crate::db::entity::{
        local_user as db_local_user, password as db_password, user as db_user,
    };

    pub(super) fn get_user_mock<U: AsRef<str>>(user_id: U) -> db_user::Model {
        db_user::Model {
            id: user_id.as_ref().into(),
            domain_id: "foo_domain".into(),
            enabled: Some(true),
            ..Default::default()
        }
    }

    pub(super) fn get_local_user_with_password_mock<U: AsRef<str>>(
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
