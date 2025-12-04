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

use chrono::NaiveDate;
use serde_json::Value;
use tracing::error;

use crate::db::entity::user as db_user;
use crate::identity::types::*;

mod create;
mod delete;
mod get;
mod list;
mod set;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub(super) use get::get_main_entry;
pub use list::list;
pub use set::reset_last_active;

impl UserResponseBuilder {
    /// Merge the `user` table entry with corresponding user options into the
    /// [`UserResponseBuilder`].
    ///
    /// Update the [`UserResponseBuilder`] with the details from the main `user`
    /// table row and the corresponding user options.
    ///
    /// Calculates the [`UserResponse.enabled`](field@UserResponse::enabled)
    /// property according to the following logic:
    ///  - When [`user.enabled`](field@db_user::Model::enabled) is `false` =>
    ///    `false`
    ///  - When [`ignore_user_inactivity`](field@
    ///    UserOptions::ignore_user_inactivity) is true => `true`
    ///  - Otherwise when both set returns
    ///    [`user.last_active_at`](field@db_user::Model::last_active_at) `>
    ///    last_activity_cutof_date`. Returns `true` when one or both are unset.
    ///  - Defaults to `false`
    pub(super) fn merge_user_data(
        &mut self,
        user: &db_user::Model,
        options: &UserOptions,
        last_activity_cutof_date: Option<&NaiveDate>,
    ) -> &mut Self {
        self.id(user.id.clone());
        self.domain_id(user.domain_id.clone());
        self.enabled(if user.enabled.is_some_and(|val| val) {
            // Only look at the last_activity when the user is enabled.
            if let (Some(last_active_at), Some(cutoff)) =
                (&user.last_active_at, &last_activity_cutof_date)
            {
                options.ignore_user_inactivity.is_some_and(|val| val) || last_active_at > cutoff
            } else {
                // Either last_active_at or cutoff date empty - user is active
                true
            }
        } else {
            false
        });
        if let Some(extra) = &user.extra {
            self.extra(
                serde_json::from_str::<Value>(extra)
                    .inspect_err(|e| error!("failed to deserialize user extra: {e}"))
                    .unwrap_or_default(),
            );
        }
        self.options(options.clone());
        self
    }
}

#[cfg(test)]
pub(super) mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::json;

    use super::*;
    use crate::{db::entity::user as db_user, identity::types::UserResponseBuilder};

    pub fn get_user_mock<U: AsRef<str>>(user_id: U) -> db_user::Model {
        db_user::Model {
            id: user_id.as_ref().into(),
            domain_id: "foo_domain".into(),
            enabled: Some(true),
            ..Default::default()
        }
    }

    fn get_user_builder() -> db_user::ModelBuilder {
        let mut builder = db_user::ModelBuilder::default();
        builder.id("user_id");
        builder.domain_id("domain_id");
        builder
    }

    #[test]
    fn get_merge_user_data() {
        let mut builder = UserResponseBuilder::default();

        let opts = UserOptions {
            ignore_password_expiry: Some(true),
            ..Default::default()
        };
        builder.name("user_name").merge_user_data(
            &get_user_builder()
                .enabled(true)
                .last_active_at(Utc::now().date_naive())
                .extra("{\"foo\": \"bar\"}".to_string())
                .build()
                .unwrap(),
            &opts,
            None,
        );
        let user = builder.build().unwrap();
        assert_eq!(user.id, "user_id");
        assert_eq!(user.domain_id, "domain_id");
        assert_eq!(user.options, opts);
        assert_eq!(user.extra.unwrap(), json!({"foo": "bar"}));
    }

    #[test]
    fn get_merge_user_data_enabled() {
        assert!(
            !UserResponseBuilder::default()
                .name("user_name")
                .merge_user_data(
                    &get_user_builder()
                        .enabled(false)
                        .last_active_at(Utc::now().date_naive())
                        .build()
                        .unwrap(),
                    &UserOptions::default(),
                    Some(&Utc::now().date_naive()),
                )
                .build()
                .map(|u| u.enabled)
                .unwrap(),
            "disabled user with last active now and cutof in the past is disabled"
        );
        assert!(
            UserResponseBuilder::default()
                .name("user_name")
                .merge_user_data(
                    &get_user_builder()
                        .enabled(true)
                        .last_active_at(Utc::now().date_naive())
                        .build()
                        .unwrap(),
                    &UserOptions::default(),
                    Some(&DateTime::<Utc>::MIN_UTC.date_naive()),
                )
                .build()
                .map(|u| u.enabled)
                .unwrap(),
            "last active now and cutof in the past is enabled"
        );

        assert!(
            !UserResponseBuilder::default()
                .name("user_name")
                .merge_user_data(
                    &get_user_builder()
                        .enabled(true)
                        .last_active_at(DateTime::<Utc>::MIN_UTC.date_naive())
                        .build()
                        .unwrap(),
                    &UserOptions::default(),
                    Some(&Utc::now().date_naive()),
                )
                .build()
                .map(|u| u.enabled)
                .unwrap(),
            "last active in the past and cutof now with unset exempt is disabled"
        );

        assert!(
            !UserResponseBuilder::default()
                .name("user_name")
                .merge_user_data(
                    &get_user_builder()
                        .enabled(true)
                        .last_active_at(DateTime::<Utc>::MIN_UTC.date_naive())
                        .build()
                        .unwrap(),
                    &UserOptions {
                        ignore_user_inactivity: Some(false),
                        ..Default::default()
                    },
                    Some(&Utc::now().date_naive()),
                )
                .build()
                .map(|u| u.enabled)
                .unwrap(),
            "last active in the past and cutof now with no exempt is disabled"
        );
        assert!(
            UserResponseBuilder::default()
                .name("user_name")
                .merge_user_data(
                    &get_user_builder()
                        .enabled(true)
                        .last_active_at(DateTime::<Utc>::MIN_UTC.date_naive())
                        .build()
                        .unwrap(),
                    &UserOptions {
                        ignore_user_inactivity: Some(true),
                        ..Default::default()
                    },
                    Some(&Utc::now().date_naive()),
                )
                .build()
                .map(|u| u.enabled)
                .unwrap(),
            "last active in the past and cutof now with exempt is enabled"
        );
    }
}
