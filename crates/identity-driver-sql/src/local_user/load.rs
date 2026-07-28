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

use std::collections::HashMap;

use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::{
    local_user, password,
    prelude::{LocalUser, Password},
};

/// Load local user record with passwords from database.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The optional user ID.
/// - `name`: The optional user name.
/// - `domain_id`: The optional domain ID.
///
/// # Returns
/// A `Result` containing an `Option` with the `(local_user::Model, impl
/// IntoIterator<Item = password::Model>)` if found, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn load_local_user_with_passwords<
    C: ConnectionTrait,
    S1: AsRef<str>,
    S2: AsRef<str>,
    S3: AsRef<str>,
>(
    db: &C,
    user_id: Option<S1>,
    name: Option<S2>,
    domain_id: Option<S3>,
) -> Result<
    Option<(local_user::Model, impl IntoIterator<Item = password::Model>)>,
    IdentityProviderError,
> {
    let mut select = LocalUser::find();
    if let Some(user_id) = user_id {
        select = select.filter(local_user::Column::UserId.eq(user_id.as_ref()))
    } else {
        select = select
            .filter(
                local_user::Column::Name.eq(name
                    .ok_or(IdentityProviderError::UserIdOrNameWithDomain)?
                    .as_ref()),
            )
            .filter(
                local_user::Column::DomainId.eq(domain_id
                    .ok_or(IdentityProviderError::UserIdOrNameWithDomain)?
                    .as_ref()),
            );
    }
    let results: Vec<(local_user::Model, Vec<password::Model>)> = select
        .find_with_related(Password)
        .order_by(password::Column::CreatedAtInt, Order::Desc)
        .all(db)
        .await
        .context("fetching user with passwords")?;
    Ok(results.first().cloned())
}

/// Load local user record with only its latest password from database.
///
/// Same lookup as [`load_local_user_with_passwords`] but for callers that
/// only ever consult the newest password (auth, display) and don't need the
/// full history, avoiding pulling every password row for the user.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The optional user ID.
/// - `name`: The optional user name.
/// - `domain_id`: The optional domain ID.
///
/// # Returns
/// A `Result` containing an `Option` with the `(local_user::Model,
/// Option<password::Model>)` if found, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn load_local_user_with_latest_password<
    C: ConnectionTrait,
    S1: AsRef<str>,
    S2: AsRef<str>,
    S3: AsRef<str>,
>(
    db: &C,
    user_id: Option<S1>,
    name: Option<S2>,
    domain_id: Option<S3>,
) -> Result<Option<(local_user::Model, Option<password::Model>)>, IdentityProviderError> {
    let mut select = LocalUser::find();
    if let Some(user_id) = user_id {
        select = select.filter(local_user::Column::UserId.eq(user_id.as_ref()))
    } else {
        select = select
            .filter(
                local_user::Column::Name.eq(name
                    .ok_or(IdentityProviderError::UserIdOrNameWithDomain)?
                    .as_ref()),
            )
            .filter(
                local_user::Column::DomainId.eq(domain_id
                    .ok_or(IdentityProviderError::UserIdOrNameWithDomain)?
                    .as_ref()),
            );
    }
    let Some(local_user) = select.one(db).await.context("fetching local user")? else {
        return Ok(None);
    };
    let latest_password = Password::find()
        .filter(password::Column::LocalUserId.eq(local_user.id))
        .order_by(password::Column::CreatedAtInt, Order::Desc)
        .one(db)
        .await
        .context("fetching latest user password")?;
    Ok(Some((local_user, latest_password)))
}

/// Fetch the latest password for a list of optional local user ids.
///
/// Only the newest password per user is needed by callers (password
/// expiration display), so the query is restricted to one row per
/// `local_user_id` instead of the full history.
///
/// Returns vector of optional vectors with passwords in the same order as
/// requested keeping None in place where local_user was empty.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_ids`: The list of optional local user IDs.
///
/// # Returns
/// A `Result` containing a list of optional password vectors, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn load_local_users_passwords<
    C: ConnectionTrait,
    L: IntoIterator<Item = Option<i32>> + std::fmt::Debug,
>(
    db: &C,
    user_ids: L,
) -> Result<Vec<Option<Vec<password::Model>>>, IdentityProviderError> {
    let ids: Vec<Option<i32>> = user_ids.into_iter().collect();
    // Collect local user IDs that we need to query
    let keys: Vec<i32> = ids.iter().filter_map(Option::as_ref).copied().collect();

    // Fetch only the latest password per local user by keys
    let passwords: Vec<password::Model> = Password::find()
        .filter(password::Column::LocalUserId.is_in(keys.clone()))
        .distinct_on([password::Column::LocalUserId])
        .order_by(password::Column::LocalUserId, Order::Asc)
        .order_by(password::Column::CreatedAtInt, Order::Desc)
        .all(db)
        .await
        .context("fetching user passwords")?;

    // Prepare hashmap of passwords per local_user_id from requested users
    let mut hashmap: HashMap<i32, Vec<password::Model>> =
        keys.iter().fold(HashMap::new(), |mut acc, key| {
            acc.insert(*key, Vec::new());
            acc
        });

    // Collect passwords into hashmap by the local_user_id
    passwords.into_iter().for_each(|item| {
        hashmap
            .entry(item.local_user_id)
            .and_modify(|e| e.push(item.clone()))
            .or_insert_with(|| Vec::from([item]));
    });

    // Prepare final result keeping the order of the requested local_users
    // with vec of passwords for the ones
    let result: Vec<Option<Vec<password::Model>>> = ids
        .iter()
        .map(|lid| lid.map(|x| hashmap.get(&x).cloned()).unwrap_or_default())
        .collect();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;
    use crate::local_user::tests::*;

    #[tokio::test]
    async fn test_load_local_user_with_passwords_user_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_local_user_with_password_mock("user_id", 5)])
            .into_connection();
        load_local_user_with_passwords(&db, Some("user_id"), None::<String>, None::<String>)
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC, "password"."created_at_int" DESC"#,
                ["user_id".into(),]
            ),]
        );
    }

    #[tokio::test]
    async fn test_load_local_user_with_passwords_user_name_domain_ignored_for_user_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_local_user_with_password_mock("user_id", 5)])
            .into_connection();
        load_local_user_with_passwords(&db, Some("user_id"), Some("foo"), Some("bar"))
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC, "password"."created_at_int" DESC"#,
                ["user_id".into(),]
            ),]
        );
    }

    #[tokio::test]
    async fn test_load_local_user_with_passwords_no_user_name_and_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        match load_local_user_with_passwords(&db, None::<String>, Some("user_name"), None::<String>)
            .await
        {
            Err(IdentityProviderError::UserIdOrNameWithDomain) => {}
            _ => {
                panic!("User name without ID should be rejected")
            }
        };
        match load_local_user_with_passwords(&db, None::<String>, None::<String>, Some("domain_id"))
            .await
        {
            Err(IdentityProviderError::UserIdOrNameWithDomain) => {}
            _ => {
                panic!("Domain ID without user name should be rejected")
            }
        };
    }

    #[tokio::test]
    async fn test_load_local_user_with_passwords_user_name_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_local_user_with_password_mock("user_id", 5)])
            .into_connection();
        load_local_user_with_passwords(&db, None::<String>, Some("foo"), Some("bar"))
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."name" = $1 AND "local_user"."domain_id" = $2 ORDER BY "local_user"."id" ASC, "password"."created_at_int" DESC"#,
                ["foo".into(), "bar".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_load_local_user_with_latest_password_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_local_user_mock("user_id")]])
            .append_query_results([vec![password::Model {
                id: 1,
                local_user_id: 1,
                self_service: false,
                expires_at: None,
                password_hash: Some("hash".into()),
                created_at: chrono::Utc::now().naive_utc(),
                created_at_int: 1,
                expires_at_int: None,
            }]])
            .into_connection();
        let result =
            load_local_user_with_latest_password(&db, Some("user_id"), None::<&str>, None::<&str>)
                .await
                .unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().1.is_some());

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "local_user"."id", "local_user"."user_id", "local_user"."domain_id", "local_user"."name", "local_user"."failed_auth_count", "local_user"."failed_auth_at" FROM "local_user" WHERE "local_user"."user_id" = $1 LIMIT $2"#,
                    ["user_id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "password"."id", "password"."local_user_id", "password"."self_service", "password"."created_at", "password"."expires_at", "password"."password_hash", "password"."created_at_int", "password"."expires_at_int" FROM "password" WHERE "password"."local_user_id" = $1 ORDER BY "password"."created_at_int" DESC LIMIT $2"#,
                    [1i32.into(), 1u64.into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_load_local_user_with_latest_password_no_local_user() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<local_user::Model>::new()])
            .into_connection();
        let result =
            load_local_user_with_latest_password(&db, Some("user_id"), None::<&str>, None::<&str>)
                .await
                .unwrap();
        assert!(result.is_none());

        // Only the local_user lookup should run: no password query issued
        // once the user is not found.
        assert_eq!(db.into_transaction_log().len(), 1);
    }

    #[tokio::test]
    async fn test_load_local_users_passwords_only_latest_per_user() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![password::Model {
                id: 2,
                local_user_id: 1,
                self_service: false,
                expires_at: None,
                password_hash: Some("latest".into()),
                created_at: chrono::Utc::now().naive_utc(),
                created_at_int: 2,
                expires_at_int: None,
            }]])
            .into_connection();
        let result = load_local_users_passwords(&db, [Some(1)]).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].as_ref().unwrap().len(), 1);
        assert_eq!(
            result[0].as_ref().unwrap()[0].password_hash,
            Some("latest".into())
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT DISTINCT ON ("local_user_id") "password"."id", "password"."local_user_id", "password"."self_service", "password"."created_at", "password"."expires_at", "password"."password_hash", "password"."created_at_int", "password"."expires_at_int" FROM "password" WHERE "password"."local_user_id" IN ($1) ORDER BY "password"."local_user_id" ASC, "password"."created_at_int" DESC"#,
                [1i32.into()]
            ),]
        );
    }
}
