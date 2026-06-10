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

use secrecy::ExposeSecret;
use secrecy::SecretString;

use openstack_keystone_config::Config;
use openstack_keystone_core::auth::AuthenticationError;
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

/// Update user password with verification and history check.
///
/// Resolves user_id to local_user_id, verifies original password, checks
/// password history for reuse, then sets the new password.
///
/// # Parameters
/// - `db`: The database connection.
/// - `conf`: The service configuration.
/// - `user_id`: The user ID.
/// - `original_password`: The current password for verification.
/// - `new_password`: The new password to set.
///
/// # Returns
/// A `Result` containing `()` if successful, or an `Error`.
pub async fn update_password(
    db: &sea_orm::DatabaseConnection,
    conf: &Config,
    user_id: &str,
    original_password: SecretString,
    new_password: SecretString,
) -> Result<(), IdentityProviderError> {
    // Load local user with passwords
    let (local_user, passwords) =
        load_local_user_with_passwords(db, Some(user_id), None::<&str>, None::<&str>)
            .await?
            .ok_or(IdentityProviderError::UserNotFound(user_id.to_string()))?;

    // Get the latest password hash for verification
    let passwords_vec: Vec<db_password::Model> = passwords.into_iter().collect();
    let latest_password =
        passwords_vec
            .first()
            .ok_or(IdentityProviderError::NoPasswordsForUser(
                user_id.to_string(),
            ))?;

    let expected_hash =
        latest_password
            .password_hash
            .as_ref()
            .ok_or(IdentityProviderError::NoPasswordHash(
                latest_password.id.to_string(),
            ))?;

    // Verify original password
    if !password_hashing::verify_password(conf, original_password.expose_secret(), expected_hash)
        .await
        .map_err(IdentityProviderError::password_hash)?
    {
        return Err(AuthenticationError::UserNameOrPasswordWrong.into());
    }

    // Set the new password (reuse pre-loaded passwords, history check is inside)
    super::password::set_new_password(db, conf, local_user.id, new_password, passwords_vec).await?;

    Ok(())
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
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use secrecy::SecretString;

    use openstack_keystone_config::{Config, PasswordHashingAlgo};
    use openstack_keystone_core::auth::AuthenticationError;
    use openstack_keystone_core::identity::IdentityProviderError;

    use crate::entity::{local_user as db_local_user, password as db_password};

    use super::update_password;

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
    /// Create a mock local user with multiple passwords with specific IDs and
    /// created_at_int values.
    pub fn get_local_user_with_passwords_mock(
        user_id: &str,
        passwords: &[db_password::Model],
    ) -> Vec<(db_local_user::Model, db_password::Model)> {
        let lu = db_local_user::Model {
            id: 1,
            user_id: user_id.into(),
            domain_id: "foo_domain".into(),
            name: "Apple Cake".to_owned(),
            failed_auth_count: Some(0),
            failed_auth_at: Some(Utc::now().naive_utc()),
        };
        passwords
            .iter()
            .map(|pw| (lu.clone(), pw.clone()))
            .collect()
    }
    // TODO: implement test for `UserCreate::to_local_user_active_model`

    // -- test helpers for update_password tests --

    fn get_local_user_with_password_hash_mock<H: Into<String>>(
        user_id: &str,
        password_hash: H,
    ) -> Vec<(db_local_user::Model, db_password::Model)> {
        let lu = db_local_user::Model {
            id: 1,
            user_id: user_id.into(),
            domain_id: "foo_domain".into(),
            name: "Apple Cake".to_owned(),
            failed_auth_count: Some(0),
            failed_auth_at: Some(Utc::now().naive_utc()),
        };
        let password = db_password::Model {
            id: 1,
            local_user_id: 1,
            self_service: false,
            expires_at: None,
            password_hash: Some(password_hash.into()),
            created_at: Utc::now().naive_utc(),
            created_at_int: 12345,
            expires_at_int: None,
        };
        vec![(lu, password)]
    }

    fn get_local_user_with_multiple_passwords_mock(
        user_id: &str,
        password_hashes: Vec<String>,
    ) -> Vec<(db_local_user::Model, db_password::Model)> {
        let lu = db_local_user::Model {
            id: 1,
            user_id: user_id.into(),
            domain_id: "foo_domain".into(),
            name: "Apple Cake".to_owned(),
            failed_auth_count: Some(0),
            failed_auth_at: Some(Utc::now().naive_utc()),
        };
        let mut results = Vec::new();
        for (i, hash) in password_hashes.into_iter().enumerate() {
            let password = db_password::Model {
                id: (i + 1) as i32,
                local_user_id: 1,
                self_service: false,
                expires_at: None,
                password_hash: Some(hash),
                created_at: Utc::now().naive_utc(),
                created_at_int: (12345 - i as i64),
                expires_at_int: None,
            };
            results.push((lu.clone(), password));
        }
        results
    }

    fn get_config_none_hashing() -> Config {
        let mut config = Config::default();
        config.identity.password_hashing_algorithm = PasswordHashingAlgo::None;
        config
    }

    fn get_config_none_hashing_with_history(count: u16) -> Config {
        let mut config = get_config_none_hashing();
        config.security_compliance.unique_last_password_count = Some(count);
        config
    }

    #[tokio::test]
    async fn test_update_password_success_basic() {
        let config = get_config_none_hashing();
        let original_password = "old_password";
        let new_password = "new_password";

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_local_user_with_password_hash_mock(
                "user_id",
                original_password,
            )])
            // unique=0: delete 1 existing password (id=1)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            // Insert new password
            .append_query_results([vec![
                db_password::ModelBuilder::default()
                    .password_hash(new_password)
                    .build()
                    .unwrap(),
            ]])
            .into_connection();

        let result = update_password(
            &db,
            &config,
            "user_id",
            SecretString::from(original_password),
            SecretString::from(new_password),
        )
        .await;

        assert!(
            result.is_ok(),
            "update password should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_password_wrong_original_password() {
        let config = get_config_none_hashing();
        let stored_password = "correct_password";

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_local_user_with_password_hash_mock(
                "user_id",
                stored_password,
            )])
            .into_connection();

        let result = update_password(
            &db,
            &config,
            "user_id",
            SecretString::from("wrong_password"),
            SecretString::from("new_password"),
        )
        .await;

        assert!(
            matches!(
                result,
                Err(IdentityProviderError::Authentication {
                    source: AuthenticationError::UserNameOrPasswordWrong
                })
            ),
            "wrong original password should be rejected, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_password_user_not_found() {
        let config = get_config_none_hashing();

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<(db_local_user::Model, db_password::Model)>::new()])
            .into_connection();

        let result = update_password(
            &db,
            &config,
            "nonexistent_user",
            SecretString::from("old_password"),
            SecretString::from("new_password"),
        )
        .await;

        assert!(
            matches!(result, Err(IdentityProviderError::UserNotFound(ref uid)) if uid == "nonexistent_user"),
            "nonexistent user should return UserNotFound, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_password_no_password_hash() {
        let config = get_config_none_hashing();

        let lu = db_local_user::Model {
            id: 1,
            user_id: "user_id".into(),
            domain_id: "foo_domain".into(),
            name: "Apple Cake".to_owned(),
            failed_auth_count: Some(0),
            failed_auth_at: Some(Utc::now().naive_utc()),
        };
        let password_no_hash = db_password::Model {
            id: 1,
            local_user_id: 1,
            self_service: false,
            expires_at: None,
            password_hash: None,
            created_at: Utc::now().naive_utc(),
            created_at_int: 12345,
            expires_at_int: None,
        };

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![(lu, password_no_hash)]])
            .into_connection();

        let result = update_password(
            &db,
            &config,
            "user_id",
            SecretString::from("old_password"),
            SecretString::from("new_password"),
        )
        .await;

        assert!(
            matches!(result, Err(IdentityProviderError::NoPasswordHash(ref id)) if id == "1"),
            "user with no password hash should return NoPasswordHash, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_password_history_reuse_rejected() {
        let config = get_config_none_hashing_with_history(2);
        let current_password = "current_password";
        let old_password_1 = "old_password_1";
        let old_password_2 = "old_password_2";

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_local_user_with_multiple_passwords_mock(
                "user_id",
                vec![
                    current_password.to_string(),
                    old_password_1.to_string(),
                    old_password_2.to_string(),
                ],
            )])
            .into_connection();

        let result = update_password(
            &db,
            &config,
            "user_id",
            SecretString::from(current_password),
            SecretString::from(old_password_1),
        )
        .await;

        assert!(
            matches!(
                result,
                Err(IdentityProviderError::SecurityCompliance(ref _e))
            ),
            "reusing a password from history should be rejected, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_password_history_reuse_rejected_only_within_count() {
        let config = get_config_none_hashing_with_history(1);
        let current_password = "current_password";
        let old_password_1 = "old_password_1";
        let old_password_2 = "old_password_2";

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_local_user_with_multiple_passwords_mock(
                "user_id",
                vec![
                    current_password.to_string(),
                    old_password_1.to_string(),
                    old_password_2.to_string(),
                ],
            )])
            // Expire newest 1 (current_password, id=1)
            .append_query_results([vec![
                db_password::ModelBuilder::default().id(1).build().unwrap(),
            ]])
            // Delete 2 older (old_password_1 id=2, old_password_2 id=3)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
            ])
            // Insert new password
            .append_query_results([vec![
                db_password::ModelBuilder::default()
                    .password_hash(old_password_2)
                    .build()
                    .unwrap(),
            ]])
            .into_connection();

        let result = update_password(
            &db,
            &config,
            "user_id",
            SecretString::from(current_password),
            SecretString::from(old_password_2),
        )
        .await;

        assert!(
            result.is_ok(),
            "old_password_2 is beyond history count (unique=1), should be allowed, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_password_history_disabled_allows_any_password() {
        let config = get_config_none_hashing();
        let current_password = "current_password";

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_local_user_with_multiple_passwords_mock(
                "user_id",
                vec![current_password.to_string(), current_password.to_string()],
            )])
            // unique=0: delete all 2 existing passwords
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
            ])
            // Insert new password
            .append_query_results([vec![
                db_password::ModelBuilder::default()
                    .password_hash(current_password)
                    .build()
                    .unwrap(),
            ]])
            .into_connection();

        let result = update_password(
            &db,
            &config,
            "user_id",
            SecretString::from(current_password),
            SecretString::from(current_password),
        )
        .await;

        assert!(
            result.is_ok(),
            "password history disabled (unique=0), reusing current password should be allowed, got: {:?}",
            result
        );
    }
}
