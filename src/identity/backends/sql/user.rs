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

use derive_builder::Builder;
use sea_orm::FromQueryResult;
use sea_orm::entity::prelude::*;
use serde_json::Value;
use tracing::error;

use crate::db::entity::user as db_user;
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

/// Main `user` row model with additional fields.
///
/// Model for the custom query selecting the inactivity status directly from
/// the database.
#[derive(Builder, Default, FromQueryResult)]
#[builder(setter(into, strip_option))]
pub(super) struct ExtendedUserRow {
    #[builder(default)]
    pub id: String,
    #[builder(default)]
    #[sea_orm(column_type = "Text", nullable)]
    pub extra: Option<String>,
    #[builder(default)]
    pub enabled: Option<bool>,
    #[builder(default)]
    pub default_project_id: Option<String>,
    #[builder(default)]
    pub created_at: Option<DateTime>,
    #[builder(default)]
    pub last_active_at: Option<Date>,
    #[builder(default)]
    pub domain_id: String,
    #[builder(default)]
    #[sea_orm(from_col = "is_inactive")]
    pub is_inactive: bool,
}

pub fn get_user_builder(user: &ExtendedUserRow, opts: UserOptions) -> UserResponseBuilder {
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

    user_builder.options(opts);

    user_builder
}

#[cfg(test)]
pub(super) mod tests {
    use crate::db::entity::user as db_user;
    use sea_orm::{IntoMockRow, Value};
    use std::collections::BTreeMap;

    use super::*;

    impl IntoMockRow for ExtendedUserRow {
        fn into_mock_row(self) -> sea_orm::MockRow {
            BTreeMap::from([
                ("id", Value::from(self.id)),
                ("domain_id", Value::from(self.domain_id)),
                ("enabled", Value::from(self.enabled)),
                ("extra", Value::from(self.extra)),
                ("created_at", Value::from(self.created_at)),
                ("last_active_at", Value::from(self.last_active_at)),
                ("is_inactive", Value::from(self.is_inactive)),
            ])
            .into_mock_row()
        }
    }

    pub fn get_user_mock<U: AsRef<str>>(user_id: U) -> db_user::Model {
        db_user::Model {
            id: user_id.as_ref().into(),
            domain_id: "foo_domain".into(),
            enabled: Some(true),
            ..Default::default()
        }
    }
}
