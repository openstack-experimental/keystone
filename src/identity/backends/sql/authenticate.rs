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
//! Authentication implementation.
use chrono::Utc;
use sea_orm::DatabaseConnection;
use tracing::info;

use super::local_user;
use super::user;
use super::user_option;
use crate::auth::{AuthenticatedInfo, AuthenticationError};
use crate::config::Config;
use crate::db::entity::{local_user as db_local_user, password as db_password};
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::backends::sql::password;
use crate::identity::password_hashing;
use crate::identity::types::*;

/// Authenticate a user by a password.
///
/// Verify whether the passed password matches the one recorded in the database and that the user
/// is allowed to login (i.e. not locked).
///
/// - Reads local user database entry with passwords sorted by the creation date (desc).
/// - Reads user options if the user has been found.
/// - Checks whether the user is locked due to the amount of failed attempts (PCI-DSS).
/// - Verifies the password matches the most recent created hash.
/// - Verifies the password is not expired.
/// - Reads main user database entry.
/// - Converts all responses into the [`UserResponse`] structure.
pub async fn authenticate_by_password(
    config: &Config,
    db: &DatabaseConnection,
    auth: &UserPasswordAuthRequest,
) -> Result<AuthenticatedInfo, IdentityDatabaseError> {
    let user_with_passwords = local_user::load_local_user_with_passwords(
        db,
        auth.id.as_ref(),
        auth.name.as_ref(),
        auth.domain.as_ref().and_then(|x| x.id.as_ref()),
    )
    .await?;

    let (local_user, password) =
        user_with_passwords.ok_or(AuthenticationError::UserNameOrPasswordWrong)?;
    // User has been found.
    // Get user options
    let user_opts = user_option::list_by_user_id(db, local_user.user_id.clone()).await?;

    // Check for the temporary lock
    if !user_opts
        .ignore_lockout_failure_attempts
        .is_some_and(|val| val)
        && is_account_locked(config, db, &local_user).await?
    {
        return Err(AuthenticationError::UserLocked(local_user.user_id.clone()))?;
    }

    let passwords: Vec<db_password::Model> = password.into_iter().collect();
    let latest_password = passwords
        .first()
        .ok_or(IdentityDatabaseError::NoPasswordsForUser(
            local_user.user_id.clone(),
        ))?;
    let expected_hash =
        latest_password
            .password_hash
            .as_ref()
            .ok_or(IdentityDatabaseError::NoPasswordHash(
                latest_password.id.clone().to_string(),
            ))?;

    // Verify the password
    if !password_hashing::verify_password(config, &auth.password, expected_hash).await? {
        return Err(AuthenticationError::UserNameOrPasswordWrong)?;
    }
    // Check if expired password exempt is on
    if !user_opts.ignore_password_expiry.is_some_and(|val| val) {
        // otherwise check for expired password
        if password::is_password_expired(latest_password)? {
            return Err(AuthenticationError::UserPasswordExpired(
                local_user.user_id.clone(),
            ))?;
        }
    }

    let user = user::get_main_entry(db, &local_user.user_id).await?.ok_or(
        IdentityDatabaseError::NoMainUserEntry(local_user.user_id.clone()),
    )?;
    let user =
        local_user::get_local_user_builder(config, &user, local_user, Some(passwords), user_opts)
            .build()?;
    Ok(AuthenticatedInfo::builder()
        .user_id(user.id.clone())
        .user(user)
        .methods(vec!["password".into()])
        .build()
        .map_err(AuthenticationError::from)?)
}

/// Verify whether the account is temporarily locked according to the security
/// compliance requirements.
///
/// Checks whether the account is locked temporarily due to the failed login
/// attempts as described by
/// [ADR-10](https://openstack-experimental.github.io/keystone/adr/0010-pci-dss-failed-auth-protection.html)
#[tracing::instrument(level = "debug", skip(config, db))]
async fn is_account_locked(
    config: &Config,
    db: &DatabaseConnection,
    local_user: &db_local_user::Model,
) -> Result<bool, IdentityDatabaseError> {
    if let Some(lockout_failure_attempts) = config.security_compliance.lockout_failure_attempts
        && let Some(attempts) = local_user.failed_auth_count
        && attempts >= lockout_failure_attempts.into()
    {
        if let Some(lockout_duration) = config.security_compliance.lockout_duration {
            if let Some(locked_till) = local_user
                .failed_auth_at
                .and_then(|last_failure| last_failure.checked_add_signed(lockout_duration))
            {
                // last_failure is recorded
                if locked_till > Utc::now().naive_utc() {
                    // Lock is still active
                    return Ok(true);
                }
            }
            // Either last failed_auth_at is missing or expired - reset.
            local_user::reset_failed_auth(db, local_user).await?;
        } else if !config
            .security_compliance
            .lockout_duration
            .is_some_and(|val| val.is_zero())
        {
            info!(
                "[security_compliance].lockout_duration is unset. The user is permanently locked out."
            );
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use tracing_test::traced_test;

    use crate::identity::types::user::*;
    use crate::{db::entity::local_user as db_local_user, identity::types::UserOptions};

    use super::*;

    #[tokio::test]
    async fn test_is_account_locked_default_config() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        let config = Config::default();
        assert!(
            !is_account_locked(&config, &db, &db_local_user::Model::default(),)
                .await
                .unwrap(),
            "Default config does not request any validation and user is not considered locked"
        );
    }

    #[tokio::test]
    async fn test_is_account_locked_no_failed_auth_count() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        assert!(
            !is_account_locked(
                &config,
                &db,
                &db_local_user::Model {
                    failed_auth_count: None,
                    failed_auth_at: None,
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
            "User with unset failed_auth props is not considered locked"
        );
        assert!(
            !is_account_locked(
                &config,
                &db,
                &db_local_user::Model {
                    failed_auth_count: None,
                    failed_auth_at: Some(Utc::now().naive_utc()),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
            "User with unset failed_auth_count props is not considered locked"
        );
    }

    #[tokio::test]
    async fn test_is_account_locked_no_failed_auth_at() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_local_user::Model::default()]])
            .into_connection();
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        assert!(
            !is_account_locked(
                &config,
                &db,
                &db_local_user::Model {
                    failed_auth_count: Some(10),
                    failed_auth_at: None,
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
            "User with unset failed_auth_at props is not considered locked and auth reset"
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "local_user" SET "failed_auth_count" = $1, "failed_auth_at" = $2 WHERE "local_user"."id" = $3 RETURNING "id", "user_id", "domain_id", "name", "failed_auth_count", "failed_auth_at""#,
                [
                    None::<i32>.into(),
                    None::<NaiveDateTime>.into(),
                    1i32.into()
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_is_account_locked_expired() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_local_user::Model::default()]])
            .into_connection();
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        config.security_compliance.lockout_duration = Some(TimeDelta::seconds(100));
        assert!(
            !is_account_locked(
                &config,
                &db,
                &db_local_user::Model {
                    failed_auth_count: Some(10),
                    failed_auth_at: Some(
                        Utc::now()
                            .checked_sub_signed(TimeDelta::seconds(101))
                            .unwrap()
                            .naive_utc()
                    ),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
            "User with unset expired protection is unlocked"
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "local_user" SET "failed_auth_count" = $1, "failed_auth_at" = $2 WHERE "local_user"."id" = $3 RETURNING "id", "user_id", "domain_id", "name", "failed_auth_count", "failed_auth_at""#,
                [
                    None::<i32>.into(),
                    None::<NaiveDateTime>.into(),
                    1i32.into()
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_is_account_locked_lock() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        assert!(
            is_account_locked(
                &config,
                &db,
                &db_local_user::Model {
                    failed_auth_count: Some(10),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
            "User with failed_auth_count > lockout_failure_attempts is locked for lockout_duration",
        );
        assert!(
            is_account_locked(
                &config,
                &db,
                &db_local_user::Model {
                    failed_auth_count: Some(5),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
            "User with failed_auth_count = lockout_failure_attempts is locked for lockout_duration",
        );
        assert!(
            !is_account_locked(
                &config,
                &db,
                &db_local_user::Model {
                    failed_auth_count: Some(4),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
            "User with failed_auth_count < lockout_failure_attempts is locked for lockout_duration",
        );
    }

    fn get_local_user_with_password_mock(
        password_hash: String,
    ) -> (db_local_user::Model, db_password::Model) {
        (
            db_local_user::Model::default(),
            db_password::ModelBuilder::default()
                .password_hash(password_hash)
                .build()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_authenticate() {
        let config = Config::default();
        let password = String::from("pass");
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_local_user_with_password_mock(
                password_hashing::hash_password(&config, &password)
                    .await
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(
                &UserOptions::default(),
            )])
            .append_query_results([vec![user::tests::get_user_mock("1")]])
            .into_connection();
        assert!(
            authenticate_by_password(
                &config,
                &db,
                &UserPasswordAuthRequest {
                    id: Some("user_id".into()),
                    password,
                    ..Default::default()
                },
            )
            .await
            .is_ok(),
            "unlocked user with correct password should be allowed to login"
        );
    }

    #[tokio::test]
    async fn test_authenticate_locked_user() {
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![(
                db_local_user::Model {
                    id: 1,
                    user_id: "user_id".into(),
                    domain_id: "foo_domain".into(),
                    name: "foo_domain".into(),
                    failed_auth_count: Some(10),
                    failed_auth_at: Some(Utc::now().naive_utc()),
                },
                db_password::ModelBuilder::default()
                    .local_user_id(1)
                    .build()
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(
                &UserOptions::default(),
            )])
            .into_connection();
        match authenticate_by_password(
            &config,
            &db,
            &UserPasswordAuthRequest {
                id: Some("user_id".into()),
                password: "password".into(),
                ..Default::default()
            },
        )
        .await
        {
            Err(IdentityDatabaseError::AuthenticationInfo {
                source: AuthenticationError::UserLocked(user_id),
            }) => {
                assert_eq!(user_id, "user_id");
            }
            other => {
                panic!("Locked user should be refused even before checking password: {other:?}",);
            }
        }
    }

    #[tokio::test]
    async fn test_authenticate_locked_user_exempt() {
        let mut config = Config::default();
        let password = "foo_pass";
        config.security_compliance.lockout_failure_attempts = Some(5);
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![(
                db_local_user::Model {
                    id: 1,
                    user_id: "user_id".into(),
                    domain_id: "foo_domain".into(),
                    name: "foo_domain".into(),
                    failed_auth_count: Some(10),
                    failed_auth_at: Some(Utc::now().naive_utc()),
                },
                db_password::ModelBuilder::default()
                    .local_user_id(1)
                    .password_hash(
                        password_hashing::hash_password(&config, &password)
                            .await
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(&UserOptions {
                ignore_lockout_failure_attempts: Some(true),
                ..Default::default()
            })])
            .append_query_results([vec![user::tests::get_user_mock("1")]])
            .into_connection();
        assert!(
            authenticate_by_password(
                &config,
                &db,
                &UserPasswordAuthRequest {
                    id: Some("user_id".into()),
                    password: password.into(),
                    ..Default::default()
                },
            )
            .await
            .is_ok(),
            "User that should be locked is still allowed due to the exempt"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_authenticate_wrong_password() {
        let config = Config::default();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![(
                db_local_user::Model::default(),
                db_password::ModelBuilder::default()
                    .password_hash("wrong_password")
                    .build()
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(
                &UserOptions::default(),
            )])
            .into_connection();
        match authenticate_by_password(
            &config,
            &db,
            &UserPasswordAuthRequest {
                id: Some("user_id".into()),
                password: "foo_pass".into(),
                ..Default::default()
            },
        )
        .await
        {
            Err(IdentityDatabaseError::AuthenticationInfo {
                source: AuthenticationError::UserNameOrPasswordWrong,
            }) => {}
            other => {
                panic!("User with wrong password should be refused: {other:?}");
            }
        }
        assert!(!logs_contain("foo_pass"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_authenticate_expired_password() {
        let config = Config::default();
        let password = String::from("foo_pass");
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![(
                db_local_user::Model::default(),
                db_password::ModelBuilder::default()
                    .password_hash(
                        password_hashing::hash_password(&config, &password)
                            .await
                            .unwrap(),
                    )
                    .expires(DateTime::<Utc>::MIN_UTC)
                    .build()
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(
                &UserOptions::default(),
            )])
            .into_connection();
        match authenticate_by_password(
            &config,
            &db,
            &UserPasswordAuthRequest {
                id: Some("user_id".into()),
                password: password.clone(),
                ..Default::default()
            },
        )
        .await
        {
            Err(IdentityDatabaseError::AuthenticationInfo {
                source: AuthenticationError::UserPasswordExpired(..),
            }) => {}
            other => {
                panic!("User with expired valid password should be refused: {other:?}");
            }
        }

        assert!(!logs_contain(&password));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_authenticate_exempt_expired_password() {
        let config = Config::default();
        let password = String::from("foo_pass");
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![(
                db_local_user::Model::default(),
                db_password::ModelBuilder::expired()
                    .password_hash(
                        password_hashing::hash_password(&config, &password)
                            .await
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(&UserOptions {
                ignore_password_expiry: Some(true),
                ..Default::default()
            })])
            .append_query_results([vec![user::tests::get_user_mock("1")]])
            .into_connection();
        assert!(
            authenticate_by_password(
                &config,
                &db,
                &UserPasswordAuthRequest {
                    id: Some("user_id".into()),
                    password: password.clone(),
                    ..Default::default()
                },
            )
            .await
            .is_ok(),
            "User with expired password and expiration exempt should be allowed"
        );

        assert!(!logs_contain(&password));
    }
}
