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

use super::super::federated_user;
use super::super::local_user;
use super::super::nonlocal_user;
use crate::config::Config;
use crate::db::entity::{
    prelude::{FederatedUser, NonlocalUser, User as DbUser, UserOption},
    user as db_user,
};
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};
use crate::identity::types::*;

pub async fn get_main_entry<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<Option<db_user::Model>, IdentityDatabaseError> {
    DbUser::find_by_id(user_id.as_ref())
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching user by ID"))
}

pub async fn get(
    conf: &Config,
    db: &DatabaseConnection,
    user_id: &str,
) -> Result<Option<UserResponse>, IdentityDatabaseError> {
    let user_select = DbUser::find_by_id(user_id);

    let user_entry: Option<db_user::Model> = user_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching the user data"))?;

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

        let user_builder: UserResponseBuilder = match local_user_with_passwords? {
            Some(local_user_with_passwords) => local_user::get_local_user_builder(
                conf,
                &user,
                local_user_with_passwords.0,
                Some(local_user_with_passwords.1),
                UserOptions::from_iter(
                    user_opts.map_err(|err| db_err(err, "fetching user options"))?,
                ),
            ),
            _ => match user
                .find_related(NonlocalUser)
                .one(db)
                .await
                .map_err(|err| db_err(err, "fetching nonlocal user data"))?
            {
                Some(nonlocal_user) => nonlocal_user::get_nonlocal_user_builder(
                    &user,
                    nonlocal_user,
                    UserOptions::from_iter(
                        user_opts.map_err(|err| db_err(err, "fetching user options"))?,
                    ),
                ),
                _ => {
                    let federated_user = user
                        .find_related(FederatedUser)
                        .all(db)
                        .await
                        .map_err(|err| db_err(err, "fetching federated user data"))?;
                    if !federated_user.is_empty() {
                        federated_user::get_federated_user_builder(
                            &user,
                            federated_user,
                            UserOptions::from_iter(
                                user_opts.map_err(|err| db_err(err, "fetching user options"))?,
                            ),
                        )
                    } else {
                        return Err(IdentityDatabaseError::MalformedUser(user_id.to_string()))?;
                    }
                }
            },
        };

        return Ok(Some(user_builder.build()?));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::config::Config;
    use crate::db::entity::user_option as db_user_option;

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_get() { //// Create MockDatabase with mock query results
        //let db = MockDatabase::new(DatabaseBackend::Postgres)
        //    .append_exec_results([MockExecResult {
        //        rows_affected: 1,
        //        ..Default::default()
        //    }])
        //    .into_connection();
        //let config = Config::default();

        //delete(&config, &db, "id").await.unwrap();
        //// Checking transaction log
        //assert_eq!(
        //    db.into_transaction_log(),
        //    [Transaction::from_sql_and_values(
        //        DatabaseBackend::Postgres,
        //        r#"DELETE FROM "user" WHERE "user"."id" = $1"#,
        //        ["id".into()]
        //    ),]
        //);
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
                ..Default::default()
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user"."id", "user"."extra", "user"."enabled", "user"."default_project_id", "user"."created_at", "user"."last_active_at", "user"."domain_id" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
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
}
