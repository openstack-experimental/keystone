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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::sea_query::Query;

use openstack_keystone_config::Config;
use openstack_keystone_core::auth::AuthenticationError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::{UserOptions, UserResponse, UserResponseBuilder};

use crate::entity::{
    federated_user as db_federated_user, local_user as db_local_user,
    nonlocal_user as db_nonlocal_user,
    prelude::{FederatedUser, LocalUser, NonlocalUser, User as DbUser, UserOption},
    user as db_user,
};
use crate::federated_user::MergeFederatedUserData;
use crate::local_user;
use crate::local_user::MergeLocalUserData;
use crate::nonlocal_user::MergeNonlocalUserData;
use crate::password::MergePasswordData;
use crate::user::MergeUserData;

/// Get the `user` table entry by the `user_id`.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID.
///
/// # Returns
/// A `Result` containing an `Option` with the `db_user::Model` if found, or an
/// `Error`.
#[tracing::instrument(skip_all)]
pub async fn get_main_entry<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<Option<db_user::Model>, IdentityProviderError> {
    Ok(DbUser::find_by_id(user_id.as_ref())
        .one(db)
        .await
        .context("fetching user by ID")?)
}

/// Get a user by its ID.
///
/// # Parameters
/// - `conf`: The system configuration.
/// - `db`: The database connection.
/// - `user_id`: The user ID.
///
/// # Returns
/// A `Result` containing an `Option` with the `UserResponse` if found, or an
/// `Error`.
#[tracing::instrument(skip_all)]
pub async fn get(
    conf: &Config,
    db: &DatabaseConnection,
    user_id: &str,
) -> Result<Option<UserResponse>, IdentityProviderError> {
    let user_entry: Option<db_user::Model> = get_main_entry(db, user_id).await?;

    if let Some(user) = user_entry {
        let (user_opts, local_user_with_passwords) = tokio::join!(
            user.find_related(UserOption).all(db),
            local_user::load_local_user_with_passwords(
                db,
                Some(&user_id),
                None::<&str>,
                None::<&str>,
            )
        );

        let mut user_builder = UserResponseBuilder::default();
        user_builder.merge_user_data(
            &user,
            &UserOptions::from_iter(user_opts.context("fetching user options")?),
            conf.security_compliance
                .get_user_last_activity_cutof_date()
                .as_ref(),
        );

        match local_user_with_passwords? {
            Some(local_user_with_passwords) => {
                user_builder.merge_local_user_data(&local_user_with_passwords.0);
                user_builder.merge_passwords_data(local_user_with_passwords.1);
            }
            _ => match NonlocalUser::find()
                .filter(db_nonlocal_user::Column::UserId.eq(&user.id))
                .one(db)
                .await
                .context("fetching nonlocal user data")?
            {
                Some(nonlocal_user) => {
                    user_builder.merge_nonlocal_user_data(&nonlocal_user);
                }
                _ => {
                    let federated_user = user
                        .find_related(FederatedUser)
                        .all(db)
                        .await
                        .context("fetching federated user data")?;
                    if !federated_user.is_empty() {
                        user_builder.merge_federated_user_data(federated_user);
                    } else {
                        return Err(IdentityProviderError::MalformedUser(user_id.to_string()));
                    }
                }
            },
        };

        return Ok(Some(user_builder.build()?));
    }

    Ok(None)
}

/// Cheaply resolve a user reference (ID, or exact name and domain ID) to the
/// canonical user ID and verify the account exists and is enabled.
///
/// This is the inexpensive existence probe backing per-user rate limiting
/// (ADR-0022, Invariant 8): point queries only, no joins, no password or
/// option loading. Name resolution checks `local_user`, `nonlocal_user`, and
/// `federated_user`, in the same order as [`get`]. The federated lookup uses a
/// subquery against the main user table because federation details do not
/// carry a domain ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID, when resolving by ID.
/// - `name`: The user name, when resolving by name.
/// - `domain_id`: The domain ID owning `name`.
///
/// # Returns
/// A `Result` containing the canonical user ID, or an `Error`
/// (`UserNotFound` when absent, `UserDisabled` when disabled).
#[tracing::instrument(skip_all)]
pub async fn check_user_exist(
    db: &DatabaseConnection,
    user_id: Option<&str>,
    name: Option<&str>,
    domain_id: Option<&str>,
) -> Result<String, IdentityProviderError> {
    let user_id: String = if let Some(id) = user_id {
        id.to_string()
    } else {
        let name = name.ok_or(IdentityProviderError::UserIdOrNameWithDomain)?;
        let domain_id = domain_id.ok_or(IdentityProviderError::UserIdOrNameWithDomain)?;
        let local: Option<String> = LocalUser::find()
            .select_only()
            .column(db_local_user::Column::UserId)
            .filter(db_local_user::Column::Name.eq(name))
            .filter(db_local_user::Column::DomainId.eq(domain_id))
            .into_tuple()
            .one(db)
            .await
            .context("resolving local user by name")?;
        match local {
            Some(id) => id,
            None => {
                let nonlocal: Option<String> = NonlocalUser::find()
                    .select_only()
                    .column(db_nonlocal_user::Column::UserId)
                    .filter(db_nonlocal_user::Column::Name.eq(name))
                    .filter(db_nonlocal_user::Column::DomainId.eq(domain_id))
                    .into_tuple()
                    .one(db)
                    .await
                    .context("resolving nonlocal user by name")?;
                match nonlocal {
                    Some(id) => id,
                    None => DbUser::find()
                        .select_only()
                        .column(db_user::Column::Id)
                        .filter(db_user::Column::DomainId.eq(domain_id))
                        .filter(
                            db_user::Column::Id.in_subquery(
                                Query::select()
                                    .column(db_federated_user::Column::UserId)
                                    .from(FederatedUser)
                                    .and_where(db_federated_user::Column::DisplayName.eq(name))
                                    .to_owned(),
                            ),
                        )
                        .into_tuple()
                        .one(db)
                        .await
                        .context("resolving federated user by name and domain")?
                        .ok_or_else(|| IdentityProviderError::UserNotFound(name.to_string()))?,
                }
            }
        }
    };

    let user = get_main_entry(db, &user_id)
        .await?
        .ok_or_else(|| IdentityProviderError::UserNotFound(user_id.clone()))?;
    if !user.enabled.unwrap_or(false) {
        return Err(AuthenticationError::UserDisabled(user_id).into());
    }
    Ok(user_id)
}

/// Get the `domain_id` of the user specified by the `user_id`.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID.
///
/// # Returns
/// A `Result` containing the domain ID, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn get_user_domain_id<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<String, IdentityProviderError> {
    DbUser::find_by_id(user_id.as_ref())
        .select_only()
        .column(db_user::Column::DomainId)
        .into_tuple()
        .one(db)
        .await
        .context("fetching domain_id of a user by ID")?
        .ok_or(IdentityProviderError::UserNotFound(
            user_id.as_ref().to_string(),
        ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, Transaction};

    use openstack_keystone_config::Config;

    use super::*;
    use crate::entity::user_option as db_user_option;
    use crate::user::tests::*;

    #[tokio::test]
    async fn test_get_main() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_mock("1")]])
            .into_connection();

        assert_eq!(
            get_main_entry(&db, "1")
                .await
                .unwrap()
                .expect("entry found"),
            get_user_mock("1")
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_get_user_local() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_user_mock("1")],
            ])
            .append_query_results([
                //// Second query result - user options
                vec![db_user_option::Model {
                    user_id: "1".into(),
                    option_id: "1000".into(),
                    option_value: Some("true".into()),
                }],
            ])
            .append_query_results([
                // Third query result - local user with passwords
                local_user::tests::get_local_user_with_password_mock("1", 1),
            ])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            get(&config, &db, "1").await.unwrap().unwrap(),
            UserResponse {
                id: "1".into(),
                domain_id: "foo_domain".into(),
                name: "Apple Cake".to_owned(),
                enabled: true,
                options: UserOptions {
                    ignore_change_password_upon_first_use: Some(true),
                    ..Default::default()
                },
                default_project_id: None,
                extra: std::collections::HashMap::new(),
                federated: None,
                password_expires_at: None
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" INNER JOIN "user" ON "user"."id" = "user_option"."user_id" WHERE "user"."id" = $1"#,
                    ["1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC, "password"."created_at_int" DESC"#,
                    ["1".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_check_user_exist_by_id_enabled() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_mock("1")]])
            .into_connection();

        assert_eq!(
            check_user_exist(&db, Some("1"), None, None).await.unwrap(),
            "1"
        );
        // Exactly one point query against the `user` table, no joins.
        let log = db.into_transaction_log();
        assert_eq!(log.len(), 1);
        let sql = &log[0].statements()[0].sql;
        assert!(!sql.contains("JOIN"), "probe must not join: {sql}");
    }

    #[tokio::test]
    async fn test_check_user_exist_by_id_disabled() {
        let mut user = get_user_mock("1");
        user.enabled = Some(false);
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![user]])
            .into_connection();

        assert!(matches!(
            check_user_exist(&db, Some("1"), None, None).await,
            Err(IdentityProviderError::Authentication {
                source:
                    openstack_keystone_core::auth::AuthenticationError::UserDisabled(id),
            }) if id == "1"
        ));
    }

    #[tokio::test]
    async fn test_check_user_exist_by_id_missing() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_user::Model>::new()])
            .into_connection();

        assert!(matches!(
            check_user_exist(&db, Some("1"), None, None).await,
            Err(IdentityProviderError::UserNotFound(id)) if id == "1"
        ));
    }

    #[tokio::test]
    async fn test_check_user_exist_by_name_and_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // local_user resolution returns the user_id tuple.
            .append_query_results([vec![
                BTreeMap::from([("user_id", Into::<Value>::into("1"))]).into_mock_row(),
            ]])
            // user table entry for the enabled check.
            .append_query_results([vec![get_user_mock("1")]])
            .into_connection();

        assert_eq!(
            check_user_exist(&db, None, Some("Apple Cake"), Some("foo_domain"))
                .await
                .unwrap(),
            "1"
        );
        // Two point queries (local_user, then user), still no joins.
        let log = db.into_transaction_log();
        assert_eq!(log.len(), 2);
        for txn in &log {
            let sql = &txn.statements()[0].sql;
            assert!(!sql.contains("JOIN"), "probe must not join: {sql}");
        }
    }

    #[tokio::test]
    async fn test_check_user_exist_by_name_falls_back_to_nonlocal() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // No local_user row for the name.
            .append_query_results([Vec::<BTreeMap<&str, Value>>::new()])
            // nonlocal_user resolution returns the user_id tuple.
            .append_query_results([vec![
                BTreeMap::from([("user_id", Into::<Value>::into("1"))]).into_mock_row(),
            ]])
            .append_query_results([vec![get_user_mock("1")]])
            .into_connection();

        assert_eq!(
            check_user_exist(&db, None, Some("Apple Cake"), Some("foo_domain"))
                .await
                .unwrap(),
            "1"
        );
        assert_eq!(db.into_transaction_log().len(), 3);
    }

    #[tokio::test]
    async fn test_check_user_exist_by_name_falls_back_to_federated() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // No local_user row for the name.
            .append_query_results([Vec::<BTreeMap<&str, Value>>::new()])
            // No nonlocal_user row for the name.
            .append_query_results([Vec::<BTreeMap<&str, Value>>::new()])
            // A federated user with this display name exists in the domain.
            .append_query_results([vec![
                BTreeMap::from([("id", Into::<Value>::into("1"))]).into_mock_row(),
            ]])
            // Main user table entry for the enabled check.
            .append_query_results([vec![get_user_mock("1")]])
            .into_connection();

        assert_eq!(
            check_user_exist(&db, None, Some("Apple Cake"), Some("foo_domain"))
                .await
                .unwrap(),
            "1"
        );

        let log = db.into_transaction_log();
        assert_eq!(log.len(), 4);
        assert!(log[0].statements()[0].sql.contains("local_user"));
        assert!(log[1].statements()[0].sql.contains("nonlocal_user"));
        let federated_sql = &log[2].statements()[0].sql;
        assert!(federated_sql.contains("federated_user"));
        assert!(federated_sql.contains("display_name"));
        assert!(federated_sql.contains("domain_id"));
        assert!(!federated_sql.contains("JOIN"));
    }

    #[tokio::test]
    async fn test_check_user_exist_by_name_missing_after_all_user_types() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<BTreeMap<&str, Value>>::new()])
            .append_query_results([Vec::<BTreeMap<&str, Value>>::new()])
            .append_query_results([Vec::<BTreeMap<&str, Value>>::new()])
            .into_connection();

        assert!(matches!(
            check_user_exist(&db, None, Some("Nobody"), Some("foo_domain")).await,
            Err(IdentityProviderError::UserNotFound(name)) if name == "Nobody"
        ));
        assert_eq!(db.into_transaction_log().len(), 3);
    }

    #[tokio::test]
    async fn test_check_user_exist_name_requires_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        assert!(matches!(
            check_user_exist(&db, None, Some("Apple Cake"), None).await,
            Err(IdentityProviderError::UserIdOrNameWithDomain)
        ));
        assert!(matches!(
            check_user_exist(&db, None, None, None).await,
            Err(IdentityProviderError::UserIdOrNameWithDomain)
        ));
    }

    #[tokio::test]
    async fn test_get_user_domain_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                BTreeMap::from([("domain_id", Into::<Value>::into("did"))]).into_mock_row(),
            ]])
            .into_connection();

        assert_eq!(get_user_domain_id(&db, "uid").await.unwrap(), "did");
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user"."domain_id" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
                ["uid".into(), 1u64.into()]
            ),]
        );
    }
}
