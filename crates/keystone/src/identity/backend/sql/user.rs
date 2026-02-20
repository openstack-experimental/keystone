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

use chrono::{DateTime, NaiveDate, Utc};
use sea_orm::entity::*;
use serde_json::{Value, json};
use tracing::error;
use uuid::Uuid;

use crate::config::Config;
use crate::db::entity::user as db_user;
use crate::identity::{IdentityProviderError, types::*};

mod create;
mod delete;
mod get;
mod list;
mod set;

pub use create::create;
pub use delete::delete;
pub(super) use get::get_main_entry;
pub use get::{get, get_user_domain_id};
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
        if let Some(extra) = &user.extra
            && extra != "{}"
        {
            match serde_json::from_str::<Value>(extra) {
                Ok(extras) => {
                    self.extra(extras);
                }
                Err(e) => {
                    error!("failed to deserialize user extra: {e}");
                }
            };
        }
        self.options(options.clone());
        self
    }
}

impl UserCreate {
    /// Get `user::ActiveModel` from the `UserCreate` request.
    pub(super) fn to_user_active_model(
        &self,
        config: &Config,
        created_at: Option<DateTime<Utc>>,
    ) -> Result<db_user::ActiveModel, IdentityProviderError> {
        let created_at = created_at.unwrap_or_else(Utc::now).naive_utc();

        Ok(db_user::ActiveModel {
            id: Set(self
                .id
                .clone()
                .unwrap_or(Uuid::new_v4().simple().to_string())),
            enabled: Set(Some(self.enabled.unwrap_or(true))),
            extra: Set(Some(serde_json::to_string(
                // For keystone it is important to have at least "{}"
                &self.extra.as_ref().or(Some(&json!({}))),
            )?)),
            default_project_id: self
                .default_project_id
                .clone()
                .map(Set)
                .unwrap_or(NotSet)
                .into(),
            // Set last_active to now if compliance disabling is on
            last_active_at: get_user_last_active_at(config, self.enabled, created_at)
                .map(Set)
                .unwrap_or(NotSet)
                .into(),
            created_at: Set(Some(created_at)),
            domain_id: Set(self.domain_id.clone()),
        })
    }
}

impl ServiceAccountCreate {
    /// Get a `db_user::ActiveModel` from the `ServiceAccountCreate` request.
    pub(super) fn to_user_active_model(
        &self,
        conf: &Config,
        created_at: Option<DateTime<Utc>>,
    ) -> Result<db_user::ActiveModel, IdentityProviderError> {
        let created_at = created_at.unwrap_or_else(Utc::now).naive_utc();

        Ok(db_user::ActiveModel {
            id: Set(self
                .id
                .clone()
                .unwrap_or(Uuid::new_v4().simple().to_string())),
            enabled: Set(Some(self.enabled.unwrap_or(true))),
            extra: Set(Some("{}".to_string())),
            default_project_id: NotSet,
            // Set last_active to now if compliance disabling is on
            last_active_at: get_user_last_active_at(conf, self.enabled, created_at)
                .map(Set)
                .unwrap_or(NotSet)
                .into(),
            created_at: Set(Some(created_at)),
            domain_id: Set(self.domain_id.clone()),
        })
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

    #[test]
    fn test_active_record_from_user_create() {
        let now = Utc::now();
        let req = UserCreateBuilder::default()
            .default_project_id("dpid")
            .domain_id("did")
            .id("1")
            .name("foo")
            .enabled(true)
            .build()
            .unwrap();
        let cfg = Config::default();
        let sot = req.to_user_active_model(&cfg, Some(now)).unwrap();
        assert_eq!(sot.default_project_id, Set(Some("dpid".into())));
        assert_eq!(sot.domain_id, Set("did".into()));
        assert_eq!(sot.enabled, Set(Some(true)));
        assert_eq!(sot.extra, Set(Some("{}".into())));
        assert_eq!(sot.id, Set("1".into()));
        assert_eq!(sot.last_active_at, NotSet);
    }

    #[test]
    fn test_active_record_from_user_create_track_user_activity() {
        let now = Utc::now();
        let req = UserCreateBuilder::default()
            .domain_id("did")
            .id("1")
            .name("foo")
            .enabled(true)
            .build()
            .unwrap();
        let mut cfg = Config::default();
        cfg.security_compliance.disable_user_account_days_inactive = Some(1);
        let sot = req.to_user_active_model(&cfg, Some(now)).unwrap();
        assert_eq!(sot.last_active_at, Set(Some(now.naive_utc().date())));
    }

    #[test]
    fn test_active_record_from_sa_create() {
        let now = Utc::now();
        let req = ServiceAccountCreate {
            domain_id: "did".into(),
            enabled: Some(true),
            id: Some("said".into()),
            name: "sa_name".into(),
        };
        let cfg = Config::default();
        let sot = req.to_user_active_model(&cfg, Some(now)).unwrap();
        assert_eq!(sot.default_project_id, NotSet);
        assert_eq!(sot.domain_id, Set("did".into()));
        assert_eq!(sot.enabled, Set(Some(true)));
        assert_eq!(sot.extra, Set(Some("{}".into())));
        assert_eq!(sot.id, Set("said".into()));
        assert_eq!(sot.last_active_at, NotSet);
    }
}
