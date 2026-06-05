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

use chrono::Utc;
use sea_orm::ConnectionTrait;
use secrecy::ExposeSecret;
use secrecy::SecretString;

use openstack_keystone_config::Config;
use openstack_keystone_core::common::password_hashing;
use openstack_keystone_core_types::identity::*;

use crate::entity::local_user as db_local_user;
use crate::entity::password as db_password;

mod create;
mod get;
mod load;
mod set;

pub use create::create;
pub use load::load_local_user_with_passwords;
pub use load::load_local_users_passwords;
pub use set::*;

/// Set a new password for the local user.
///
/// - expire all existing passwords.
/// - truncate number of old passwords to `unique_count`.
/// - add a new record with a new password
///
/// # Parameters
/// - `db`: The database connection.
/// - `local_user_id`: The local user ID.
/// - `unique_count`: Number of old passwords to keep for checking uniqueness.
/// - `password`: The password to set.
///
/// # Returns
/// A `Result` containing the created `password::Model` if successful, or an
/// `Error`.
pub async fn set_new_password<C: ConnectionTrait>(
    db: &C,
    conf: &Config,
    local_user_id: i32,
    password: SecretString,
) -> Result<db_password::Model, IdentityProviderError> {
    let now = Utc::now();
    let unique_count = conf
        .security_compliance
        .unique_last_password_count
        .unwrap_or(0);
    // Hash the new password
    let hashed_password = password_hashing::hash_password(conf, password.expose_secret())
        .await
        .map_err(IdentityProviderError::password_hash)?;

    // Calculate password expiration time
    let expires_at = conf.security_compliance.get_password_expires_at(now);
    super::password::set_new_password(db, local_user_id, unique_count, hashed_password, expires_at)
        .await
}

pub trait MergeLocalUserData {
    fn merge_local_user_data(&mut self, data: &db_local_user::Model) -> &mut Self;
}

impl MergeLocalUserData for UserResponseBuilder {
    fn merge_local_user_data(&mut self, data: &db_local_user::Model) -> &mut Self {
        self.name(data.name.clone());
        self
    }
}

#[cfg(test)]
pub mod tests {
    use chrono::Utc;

    use crate::entity::{local_user as db_local_user, password as db_password};

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
