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

use sea_orm::entity::*;

use crate::db::entity::{local_user as db_local_user, user as db_user};
use crate::identity::types::*;
use crate::{config::Config, identity::IdentityProviderError};

mod create;
mod get;
mod load;
mod set;

pub use create::create;
pub use load::load_local_user_with_passwords;
pub use load::load_local_users_passwords;
pub use set::reset_failed_auth;

impl UserResponseBuilder {
    pub fn merge_local_user_data(&mut self, data: &db_local_user::Model) -> &mut Self {
        self.name(data.name.clone());
        self
    }
}

impl UserCreate {
    /// Get `local_user::ActiveModel` from the `UserCreate` request.
    pub(in super::super) fn to_local_user_active_model(
        &self,
        config: &Config,
        main_record: &db_user::Model,
    ) -> Result<db_local_user::ActiveModel, IdentityProviderError> {
        Ok(db_local_user::ActiveModel {
            id: NotSet,
            user_id: Set(main_record.id.clone()),
            domain_id: Set(main_record.domain_id.clone()),
            name: Set(self.name.clone()),
            failed_auth_count: if main_record.enabled.is_some_and(|x| x)
                && config
                    .security_compliance
                    .disable_user_account_days_inactive
                    .is_some()
            {
                Set(Some(0))
            } else {
                NotSet
            },
            failed_auth_at: NotSet,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use chrono::Utc;

    use crate::db::entity::{local_user as db_local_user, password as db_password};

    pub fn get_local_user_mock<UID: Into<String>>(user_id: UID) -> db_local_user::Model {
        db_local_user::Model {
            id: 1,
            user_id: user_id.into(),
            domain_id: "foo_domain".into(),
            name: "foo_domain".into(),
            failed_auth_count: Some(0),
            failed_auth_at: Some(Utc::now().naive_utc()),
        }
    }

    pub fn get_local_user_with_password_mock<U: AsRef<str>>(
        user_id: U,
        cnt_password: usize,
    ) -> Vec<(db_local_user::Model, db_password::Model)> {
        let lu = db_local_user::Model {
            id: 1,
            user_id: user_id.as_ref().into(),
            domain_id: "foo_domain".into(),
            name: "Apple Cake".to_owned(),
            failed_auth_count: Some(0),
            failed_auth_at: Some(Utc::now().naive_utc()),
        };
        let mut passwords: Vec<db_password::Model> = Vec::new();
        for i in 0..cnt_password {
            passwords.push(db_password::Model {
                id: i as i32,
                local_user_id: 1,
                expires_at: None,
                self_service: false,
                password_hash: None,
                created_at: Utc::now().naive_utc(),
                created_at_int: 12345,
                expires_at_int: None,
            });
        }
        passwords
            .into_iter()
            .map(|x| (lu.clone(), x.clone()))
            .collect()
    }
    // TODO: implement test for `UserCreate::to_local_user_active_model`
}
