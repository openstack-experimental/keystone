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
//! User account authentication implementation.
use chrono::Utc;
use sea_orm::DatabaseConnection;
use tracing::info;

use openstack_keystone_config::Config;
use openstack_keystone_core::auth::*;
use openstack_keystone_core::common::password_hashing;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::{UserPasswordAuthRequest, UserResponseBuilder};

use crate::entity::{local_user as db_local_user, password as db_password};
use crate::local_user;
use crate::local_user::MergeLocalUserData;
use crate::password;
use crate::password::MergePasswordData;
use crate::user;
use crate::user::MergeUserData;
use crate::user_option;

/// Authenticate a user by a password.
///
/// Verify whether the passed password matches the one recorded in the database
/// and that the user is allowed to login (i.e. not locked).
///
/// - Reads local user database entry with passwords sorted by the creation date
///   (desc).
/// - Reads user options if the user has been found.
/// - Checks whether the user is locked due to the amount of failed attempts
///   (PCI-DSS).
/// - Verifies the password matches the most recent created hash.
/// - Verifies the password is not expired.
/// - Reads main user database entry.
/// - Converts all responses into the [`UserResponse`] structure.
///
/// # Parameters
/// - `config`: The system configuration.
/// - `db`: The database connection.
/// - `auth`: The authentication request containing user credentials.
///
/// # Returns
/// A `Result` containing the `AuthenticatedInfo` if successful, or an `Error`.
pub async fn authenticate_by_password(
    config: &Config,
    db: &DatabaseConnection,
    auth: &UserPasswordAuthRequest,
) -> Result<AuthenticationResult, IdentityProviderError> {
    let user_with_passwords = local_user::load_local_user_with_passwords(
        db,
        auth.id.as_ref(),
        auth.name.as_ref(),
        auth.domain.as_ref().and_then(|x| x.id.as_ref()),
    )
    .await?;

    let user_found = user_with_passwords.is_some();
    // Prevent timing attacks: if user is not found, generate a dummy hash and
    // verify against it to consume comparable time to the "user exists" path.
    // The `log_failed_auth` function is intentionally not called here because the
    // user does not exist and cannot be locked out. The dummy hash prevents an
    // attacker from distinguishing between "user not found" and "wrong
    // password" via timing analysis.
    if !user_found {
        // Fetch the pre-calculated dummy hash instantly from the cache
        let dummy_hash = password_hashing::get_or_init_dummy_hash(config)
            .await
            .map_err(IdentityProviderError::password_hash)?;

        let _ = password_hashing::verify_password(config, &auth.password, dummy_hash)
            .await
            .map_err(IdentityProviderError::password_hash)?;
        return Err(AuthenticationError::UserNameOrPasswordWrong.into());
    }

    let (local_user_entry, password) =
        user_with_passwords.ok_or(AuthenticationError::UserNameOrPasswordWrong)?;
    // User has been found.
    // Get user options
    let user_opts = user_option::list_by_user_id(db, local_user_entry.user_id.clone()).await?;

    // Check for the temporary lock
    if !user_opts
        .ignore_lockout_failure_attempts
        .is_some_and(|val| val)
        && should_lock(config, db, &local_user_entry).await?
    {
        return Err(AuthenticationError::UserLocked(local_user_entry.user_id.clone()).into());
    }

    // Verify user exists
    let user_entry = user::get_main_entry(db, &local_user_entry.user_id)
        .await?
        .ok_or(IdentityProviderError::NoMainUserEntry(
            local_user_entry.user_id.clone(),
        ))?;

    // Check if the user is disabled
    if !user_entry.enabled.unwrap_or(false) {
        return Err(AuthenticationError::UserDisabled(local_user_entry.user_id.clone()).into());
    }

    let passwords: Vec<db_password::Model> = password.into_iter().collect();
    let latest_password = passwords
        .first()
        .ok_or(IdentityProviderError::NoPasswordsForUser(
            local_user_entry.user_id.clone(),
        ))?;
    let expected_hash =
        latest_password
            .password_hash
            .as_ref()
            .ok_or(IdentityProviderError::NoPasswordHash(
                latest_password.id.clone().to_string(),
            ))?;

    // Verify the password
    let now = Utc::now();
    if !password_hashing::verify_password(config, &auth.password, expected_hash)
        .await
        .map_err(IdentityProviderError::password_hash)?
    {
        local_user::log_failed_auth(db, &local_user_entry, now).await?;
        return Err(AuthenticationError::UserNameOrPasswordWrong.into());
    }
    // Check if expired password exempt is on
    if !user_opts.ignore_password_expiry.is_some_and(|val| val) {
        // otherwise check for expired password
        if password::is_password_expired(latest_password)? {
            return Err(
                AuthenticationError::UserPasswordExpired(local_user_entry.user_id.clone()).into(),
            );
        }
    }

    // Reset the last_active_at for the user that successfully authenticated.
    user::reset_last_active(db, &user_entry, now).await?;

    let user_entry = UserResponseBuilder::default()
        .merge_user_data(
            &user_entry,
            &user_opts,
            config
                .security_compliance
                .get_user_last_activity_cutof_date()
                .as_ref(),
        )
        .merge_local_user_data(&local_user_entry)
        .merge_passwords_data(passwords)
        .build()?;

    Ok(AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_entry.id.clone())
                    .user(user_entry.clone())
                    .build()?,
            ),
        })
        .build()?)
}

/// Verify whether the account is temporarily locked according to the security
/// compliance requirements.
///
/// Checks whether the account is locked temporarily due to the failed login
/// attempts as described by
/// [ADR-10](https://openstack-experimental.github.io/keystone/adr/0010-pci-dss-failed-auth-protection.html)
///
/// # Parameters
/// - `config`: The system configuration.
/// - `db`: The database connection.
/// - `local_user`: The local user model to check.
///
/// # Returns
/// A `Result` containing a boolean indicating if the user should be locked, or
/// an `Error`.
#[tracing::instrument(level = "debug", skip(config, db))]
async fn should_lock(
    config: &Config,
    db: &DatabaseConnection,
    local_user: &db_local_user::Model,
) -> Result<bool, IdentityProviderError> {
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
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
    use secrecy::SecretString;
    use tracing_test::traced_test;

    use openstack_keystone_core_types::identity::UserOptions;

    use super::*;
    use crate::entity::local_user as db_local_user;
    use crate::local_user::tests::get_local_user_mock;
    use crate::user::tests::get_user_mock;

    #[tokio::test]
    async fn test_should_lock_default_config() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        let config = Config::default();
        assert!(
            !should_lock(&config, &db, &get_local_user_mock("user_id"))
                .await
                .unwrap(),
            "Default config does not request any validation and user is not considered locked"
        );
    }

    #[tokio::test]
    async fn test_should_lock_no_failed_auth_count() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        assert!(
            !should_lock(
                &config,
                &db,
                &db_local_user::Model {
                    id: 1,
                    user_id: "user_id".into(),
                    domain_id: "foo_domain".into(),
                    name: "foo_domain".into(),
                    failed_auth_count: None,
                    failed_auth_at: None,
                },
            )
            .await
            .unwrap(),
            "User with unset failed_auth props is not considered locked"
        );
        assert!(
            !should_lock(
                &config,
                &db,
                &db_local_user::Model {
                    id: 1,
                    user_id: "user_id".into(),
                    domain_id: "foo_domain".into(),
                    name: "foo_domain".into(),
                    failed_auth_count: None,
                    failed_auth_at: Some(Utc::now().naive_utc()),
                },
            )
            .await
            .unwrap(),
            "User with unset failed_auth_count props is not considered locked"
        );
    }

    #[tokio::test]
    async fn test_should_lock_no_failed_auth_at() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_local_user_mock("user_id")]])
            .into_connection();
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        assert!(
            !should_lock(
                &config,
                &db,
                &db_local_user::Model {
                    id: 1,
                    user_id: "user_id".into(),
                    domain_id: "foo_domain".into(),
                    name: "foo_domain".into(),
                    failed_auth_count: Some(10),
                    failed_auth_at: None,
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
    async fn test_should_lock_expired() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_local_user_mock("user_id")]])
            .into_connection();
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        config.security_compliance.lockout_duration = Some(TimeDelta::seconds(100));
        assert!(
            !should_lock(
                &config,
                &db,
                &db_local_user::Model {
                    id: 1,
                    user_id: "uid".into(),
                    domain_id: "did".into(),
                    name: "name".into(),
                    failed_auth_count: Some(10),
                    failed_auth_at: Some(
                        Utc::now()
                            .checked_sub_signed(TimeDelta::seconds(101))
                            .unwrap()
                            .naive_utc()
                    ),
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
    async fn test_should_lock_lock() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        let mut config = Config::default();
        config.security_compliance.lockout_failure_attempts = Some(5);
        assert!(
            should_lock(
                &config,
                &db,
                &db_local_user::Model {
                    id: 1,
                    user_id: "uid".into(),
                    domain_id: "did".into(),
                    name: "name".into(),
                    failed_auth_count: Some(10),
                    failed_auth_at: Some(Utc::now().naive_utc()),
                },
            )
            .await
            .unwrap(),
            "User with failed_auth_count > lockout_failure_attempts is locked for lockout_duration",
        );
        assert!(
            should_lock(
                &config,
                &db,
                &db_local_user::Model {
                    id: 1,
                    user_id: "uid".into(),
                    domain_id: "did".into(),
                    name: "name".into(),
                    failed_auth_count: Some(5),
                    failed_auth_at: Some(Utc::now().naive_utc()),
                },
            )
            .await
            .unwrap(),
            "User with failed_auth_count = lockout_failure_attempts is locked for lockout_duration",
        );
        assert!(
            !should_lock(
                &config,
                &db,
                &db_local_user::Model {
                    id: 1,
                    user_id: "uid".into(),
                    domain_id: "did".into(),
                    name: "name".into(),
                    failed_auth_count: Some(4),
                    failed_auth_at: Some(Utc::now().naive_utc()),
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
            get_local_user_mock("user_id"),
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
        let password_secret = SecretString::from(password.clone());
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_local_user_with_password_mock(
                password_hashing::hash_password(&config, &password_secret)
                    .await
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(
                "user_id",
                &UserOptions::default(),
            )])
            // user::get_main_entry() for enabled check
            .append_query_results([vec![user::tests::get_user_mock("user_id")]])
            // user update res for reset_last_active
            .append_query_results([vec![user::tests::get_user_mock("user_id")]])
            .into_connection();
        assert!(
            authenticate_by_password(
                &config,
                &db,
                &UserPasswordAuthRequest {
                    id: Some("user_id".into()),
                    password: password.clone().into(),
                    ..Default::default()
                },
            )
            .await
            .is_ok(),
            "unlocked user with correct password should be allowed to login"
        );

        // Checking transaction log
        let log = db.into_transaction_log();
        assert_eq!(log.len(), 4);
        assert_eq!(
            log[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC, "password"."created_at_int" DESC"#,
                ["user_id".into()]
            )
        );
        assert_eq!(
            log[1],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" WHERE "user_option"."user_id" = $1"#,
                ["user_id".into()]
            )
        );
        assert_eq!(
            log[2],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
                ["user_id".into(), 1u64.into()]
            )
        );

        // Verify the UPDATE statement for successful authentication
        let update_debug = format!("{:?}", log[3]);
        assert!(
            update_debug.contains("UPDATE \\\"user\\\" SET \\\"last_active_at\\\"")
                && update_debug.contains("user_id"),
            "UPDATE user with last_active_at not found, got: {}",
            update_debug
        );
        assert!(
            update_debug.contains("ChronoDate(Some("),
            "last_active_at should be set"
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
                "user_id",
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
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::UserLocked(user_id),
            }) => {
                assert_eq!(user_id, "user_id");
            }
            other => {
                panic!("Locked user should be refused even before checking password: {other:?}");
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
                        password_hashing::hash_password(&config, &SecretString::from(password))
                            .await
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_query_results([user_option::tests::get_user_options_mock(
                "user_id",
                &UserOptions {
                    ignore_lockout_failure_attempts: Some(true),
                    ..Default::default()
                },
            )])
            .append_query_results([vec![user::tests::get_user_mock("user_id")]])
            .append_query_results([vec![user::tests::get_user_mock("user_id")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
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
                get_local_user_mock("user_id"),
                db_password::ModelBuilder::default()
                    .password_hash("wrong_password")
                    .build()
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(
                "user_id",
                &UserOptions::default(),
            )])
            // user::get_main_entry()
            .append_query_results([vec![get_user_mock("user_id")]])
            .append_query_results([vec![get_local_user_mock("user_id")]])
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
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::UserNameOrPasswordWrong,
            }) => {}
            other => {
                panic!("User with wrong password should be refused: {other:?}");
            }
        }
        assert!(!logs_contain("foo_pass"));

        // Verify that the failure was logged
        let log = db.into_transaction_log();
        assert_eq!(log.len(), 4);

        // Verify first 3 transactions exactly
        assert_eq!(
            log[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC, "password"."created_at_int" DESC"#,
                ["user_id".into()]
            )
        );
        assert_eq!(
            log[1],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" WHERE "user_option"."user_id" = $1"#,
                ["user_id".into()]
            )
        );
        assert_eq!(
            log[2],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
                ["user_id".into(), 1u64.into()]
            )
        );

        // Verify the UPDATE statement for failed auth logging
        // timestamp (ChronoDateTime) is dynamic so we check via debug string
        let update_debug = format!("{:?}", log[3]);
        assert!(
            update_debug.contains("UPDATE \\\"local_user\\\" SET \\\"failed_auth_count\\\"")
                && update_debug.contains("\\\"failed_auth_at\\\""),
            "UPDATE local_user with failed_auth fields not found, got: {}",
            update_debug
        );
        assert!(
            update_debug.contains("Int(Some(1))"),
            "failed_auth_count should be 1"
        );
        assert!(
            update_debug.contains("Int(Some(1))"),
            "local_user id should be 1"
        );
        assert!(
            update_debug.contains("ChronoDateTime(Some("),
            "failed_auth_at should be set"
        );
    }

    #[tokio::test]
    async fn test_authenticate_user_not_found() {
        let config = Config::default();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<(db_local_user::Model, db_password::Model)>::new()])
            .into_connection();
        match authenticate_by_password(
            &config,
            &db,
            &UserPasswordAuthRequest {
                id: Some("nonexistent_user".into()),
                password: "secret".into(),
                ..Default::default()
            },
        )
        .await
        {
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::UserNameOrPasswordWrong,
            }) => {}
            other => {
                panic!("User not found should return UserNameOrPasswordWrong, got: {other:?}");
            }
        }

        // Verify that only the initial SELECT was executed (no UPDATE, no extra
        // lookups)
        let log = db.into_transaction_log();
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC, "password"."created_at_int" DESC"#,
                ["nonexistent_user".into()]
            )
        );
    }

    /// Timing consistency test: verify that "user not found" and "wrong
    /// password" take comparable time, preventing username enumeration via
    /// timing attacks.
    ///
    /// This test is #[ignore] by default because timing tests are inherently
    /// unreliable in CI environments. Run with `--ignored` flag to execute.
    #[tokio::test]
    #[ignore]
    async fn test_authenticate_timing_consistency() {
        let config = Config::default();
        let iterations = 10;

        // Measure "user not found" timing
        let mut not_found_total = std::time::Duration::ZERO;
        for _ in 0..iterations {
            let db = MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results([Vec::<(db_local_user::Model, db_password::Model)>::new()])
                .into_connection();
            let start = std::time::Instant::now();
            let _ = authenticate_by_password(
                &config,
                &db,
                &UserPasswordAuthRequest {
                    id: Some("nonexistent_user".into()),
                    password: "secret".into(),
                    ..Default::default()
                },
            )
            .await;
            not_found_total += start.elapsed();
        }

        // Measure "wrong password" timing
        let mut wrong_password_total = std::time::Duration::ZERO;
        for _ in 0..iterations {
            let db = MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results([vec![(
                    get_local_user_mock("user_id"),
                    db_password::ModelBuilder::default()
                        .password_hash("wrong_hash")
                        .build()
                        .unwrap(),
                )]])
                .append_query_results([user_option::tests::get_user_options_mock(
                    "user_id",
                    &UserOptions::default(),
                )])
                .append_query_results([vec![get_user_mock("user_id")]])
                .append_query_results([vec![get_local_user_mock("user_id")]])
                .into_connection();
            let start = std::time::Instant::now();
            let _ = authenticate_by_password(
                &config,
                &db,
                &UserPasswordAuthRequest {
                    id: Some("user_id".into()),
                    password: "secret".into(),
                    ..Default::default()
                },
            )
            .await;
            wrong_password_total += start.elapsed();
        }

        let not_found_avg = not_found_total.as_secs_f64() / iterations as f64;
        let wrong_password_avg = wrong_password_total.as_secs_f64() / iterations as f64;

        // The "user not found" path should take at least 70% of the time of the "wrong
        // password" path. If it's significantly faster, an attacker could
        // distinguish between the two paths.
        let ratio = if wrong_password_avg > 0.0 {
            not_found_avg / wrong_password_avg
        } else {
            0.0
        };

        // Allow some variance (up to 150%) to account for system noise,
        // but if the ratio is much less than 1, it indicates a leak.
        assert!(
            ratio >= 0.5,
            "Timing leak detected: user_not_found avg {:.3}s, wrong_password avg {:.3}s (ratio {:.2}).",
            not_found_avg,
            wrong_password_avg,
            ratio
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_authenticate_expired_password() {
        let config = Config::default();
        let password = String::from("foo_pass");
        let password_secret = SecretString::from(password.clone());
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![(
                get_local_user_mock("user_id"),
                db_password::ModelBuilder::default()
                    .password_hash(
                        password_hashing::hash_password(&config, &password_secret)
                            .await
                            .unwrap(),
                    )
                    .expires(DateTime::<Utc>::MIN_UTC)
                    .build()
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(
                "user_id",
                &UserOptions::default(),
            )])
            .append_query_results([vec![get_user_mock("user_id")]])
            .into_connection();
        match authenticate_by_password(
            &config,
            &db,
            &UserPasswordAuthRequest {
                id: Some("user_id".into()),
                password: password.clone().into(),
                ..Default::default()
            },
        )
        .await
        {
            Err(IdentityProviderError::Authentication {
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
        let password_secret = SecretString::from(password.clone());
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![(
                get_local_user_mock("user_id"),
                db_password::ModelBuilder::expired()
                    .password_hash(
                        password_hashing::hash_password(&config, &password_secret)
                            .await
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )]])
            .append_query_results([user_option::tests::get_user_options_mock(
                "user_id",
                &UserOptions {
                    ignore_password_expiry: Some(true),
                    ..Default::default()
                },
            )])
            .append_query_results([vec![user::tests::get_user_mock("user_id")]])
            .append_query_results([vec![user::tests::get_user_mock("user_id")]])
            .into_connection();
        assert!(
            authenticate_by_password(
                &config,
                &db,
                &UserPasswordAuthRequest {
                    id: Some("user_id".into()),
                    password: password.clone().into(),
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
