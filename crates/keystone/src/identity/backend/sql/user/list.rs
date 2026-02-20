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

use super::super::local_user;
use crate::config::Config;
use crate::db::entity::{
    federated_user as db_federated_user, local_user as db_local_user,
    nonlocal_user as db_nonlocal_user, password as db_password,
    prelude::{FederatedUser, LocalUser, NonlocalUser, User as DbUser, UserOption as DbUserOption},
    user as db_user,
};
use crate::error::DbContextExt;
use crate::identity::{
    IdentityProviderError,
    types::{UserListParameters, UserOptions, UserResponse, UserResponseBuilder, UserType},
};

/// List users.
///
/// List users in the database. Fetch matching `user` table entries first.
/// Afterwards fetch in parallel `local_user`, `nonlocal_user`,
/// `federated_user`, `user_option` entries merging results to the proper entry.
/// For the local users additionally passwords are being retrieved to identify
/// the password expiration date.
#[tracing::instrument(skip_all)]
pub async fn list(
    conf: &Config,
    db: &DatabaseConnection,
    params: &UserListParameters,
) -> Result<Vec<UserResponse>, IdentityProviderError> {
    // Prepare basic selects
    let mut user_select = DbUser::find();
    let mut local_user_select = LocalUser::find();
    let mut nonlocal_user_select = NonlocalUser::find();
    let mut federated_user_select = FederatedUser::find();

    if let Some(domain_id) = &params.domain_id {
        user_select = user_select.filter(db_user::Column::DomainId.eq(domain_id));
    }
    if let Some(name) = &params.name {
        local_user_select = local_user_select.filter(db_local_user::Column::Name.eq(name));
        nonlocal_user_select = nonlocal_user_select.filter(db_nonlocal_user::Column::Name.eq(name));
        federated_user_select =
            federated_user_select.filter(db_federated_user::Column::DisplayName.eq(name));
    }

    // Fetch main `user` entries
    let db_users: Vec<db_user::Model> = user_select.all(db).await.context("fetching users data")?;
    let count_of_users_selected = db_users.len();

    let user_type = params.user_type.unwrap_or(UserType::All);
    let (user_opts, local_users, nonlocal_users, federated_users) = tokio::join!(
        db_users.load_many(DbUserOption, db),
        // Load local users when requested, otherwise return empty results list
        async {
            if user_type == UserType::Local || user_type == UserType::All {
                db_users.load_one(local_user_select, db).await
            } else {
                Ok(vec![None; count_of_users_selected])
            }
        },
        // Load nonlocal users when requested
        async {
            if user_type == UserType::NonLocal || user_type == UserType::All {
                db_users.load_one(nonlocal_user_select, db).await
            } else {
                Ok(vec![None; count_of_users_selected])
            }
        },
        // Load federated users when requested
        async {
            if user_type == UserType::Federated || user_type == UserType::All {
                db_users.load_many(federated_user_select, db).await
            } else {
                Ok(vec![Vec::new(); count_of_users_selected])
            }
        },
    );

    let locals = local_users.context("fetching local users data")?;

    // For local users fetch passwords to determine password expiration
    let local_users_passwords: Vec<Option<Vec<db_password::Model>>> =
        if user_type == UserType::Local || user_type == UserType::All {
            local_user::load_local_users_passwords(
                db,
                locals
                    .iter()
                    .cloned()
                    .map(|u| u.map(|x| x.id))
                    .collect::<Vec<_>>(),
            )
            .await?
        } else {
            vec![None; count_of_users_selected]
        };

    // Determine the date for which users with the last activity earlier than are
    // determined as inactive.
    let last_activity_cutof_date = conf.security_compliance.get_user_last_activity_cutof_date();

    let mut results: Vec<UserResponse> = Vec::new();
    for (u, (o, (l, (p, (n, f))))) in db_users.into_iter().zip(
        user_opts.context("fetching user options")?.into_iter().zip(
            locals.into_iter().zip(
                local_users_passwords.into_iter().zip(
                    nonlocal_users
                        .context("fetching nonlocal users data")?
                        .into_iter()
                        .zip(
                            federated_users
                                .context("fetching federated users data")?
                                .into_iter(),
                        ),
                ),
            ),
        ),
    ) {
        let mut user_builder = UserResponseBuilder::default();
        user_builder.merge_user_data(
            &u,
            &UserOptions::from_iter(o),
            last_activity_cutof_date.as_ref(),
        );
        if let Some(local) = l {
            user_builder.merge_local_user_data(&local);
            if let Some(pass) = p {
                user_builder.merge_passwords_data(pass.into_iter());
            }
        } else if let Some(nonlocal) = n {
            user_builder.merge_nonlocal_user_data(&nonlocal);
        } else if !f.is_empty() {
            user_builder.merge_federated_user_data(f);
        } else {
            // No matching user details found (maybe due to the filters)
            continue;
        };
        results.push(user_builder.build()?);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::config::Config;
    use crate::db::entity::password as db_password;

    use super::super::super::federated_user::tests::*;
    use super::super::super::local_user::tests::*;
    use super::super::super::nonlocal_user::tests::*;
    use super::super::super::user_option::tests::*;
    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                // local user
                get_user_mock("1"),
                // nonlocal user
                get_user_mock("2"),
                // federated user
                get_user_mock("3"),
                // a "bad" user with no user detail records
                get_user_mock("4"),
            ]])
            .append_query_results([[
                get_user_options_mock("1", &UserOptions::default()),
                get_user_options_mock("2", &UserOptions::default()),
                get_user_options_mock("3", &UserOptions::default()),
            ]
            .into_iter()
            .flatten()])
            .append_query_results([vec![get_local_user_mock("1")]])
            .append_query_results([vec![get_nonlocal_user_mock("2")]])
            .append_query_results([vec![get_federated_user_mock("3")]])
            .append_query_results([vec![db_password::Model::default()]])
            .into_connection();

        let config = Config::default();
        let res = list(&config, &db, &UserListParameters::default())
            .await
            .unwrap();
        assert_eq!(res.len(), 3, "3 users found");

        for (l,r) in db.into_transaction_log().iter().zip([
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" WHERE "user_option"."user_id" IN ($1, $2, $3, $4)"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "local_user"."id", "local_user"."user_id", "local_user"."domain_id", "local_user"."name", "local_user"."failed_auth_count", "local_user"."failed_auth_at" FROM "local_user" WHERE ("local_user"."user_id", "local_user"."domain_id") IN (($1, $2), ($3, $4), ($5, $6), ($7, $8))"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "nonlocal_user"."domain_id", "nonlocal_user"."name", "nonlocal_user"."user_id" FROM "nonlocal_user" WHERE ("nonlocal_user"."user_id", "nonlocal_user"."domain_id") IN (($1, $2), ($3, $4), ($5, $6), ($7, $8))"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_user"."id", "federated_user"."user_id", "federated_user"."idp_id", "federated_user"."protocol_id", "federated_user"."unique_id", "federated_user"."display_name" FROM "federated_user" WHERE "federated_user"."user_id" IN ($1, $2, $3, $4)"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "password"."id", "password"."local_user_id", "password"."self_service", "password"."created_at", "password"."expires_at", "password"."password_hash", "password"."created_at_int", "password"."expires_at_int" FROM "password" WHERE "password"."local_user_id" IN ($1) ORDER BY "password"."created_at_int" DESC"#,
                    []
                ),
            ]) {
            assert_eq!(
                l.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>(),
                r.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn test_list_local_only() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                // local user
                get_user_mock("1"),
                // nonlocal user
                get_user_mock("2"),
                // federated user
                get_user_mock("3"),
                // a "bad" user with no user detail records
                get_user_mock("4"),
            ]])
            .append_query_results([[get_user_options_mock("1", &UserOptions::default())]
                .into_iter()
                .flatten()])
            .append_query_results([vec![get_local_user_mock("1")]])
            .append_query_results([vec![db_password::Model::default()]])
            .into_connection();

        let config = Config::default();
        let res = list(
            &config,
            &db,
            &UserListParameters {
                user_type: Some(UserType::Local),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 1, "1 local user found");
        for (l,r) in db.into_transaction_log().iter().zip([
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" WHERE "user_option"."user_id" IN ($1, $2, $3, $4)"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "local_user"."id", "local_user"."user_id", "local_user"."domain_id", "local_user"."name", "local_user"."failed_auth_count", "local_user"."failed_auth_at" FROM "local_user" WHERE ("local_user"."user_id", "local_user"."domain_id") IN (($1, $2), ($3, $4), ($5, $6), ($7, $8))"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "password"."id", "password"."local_user_id", "password"."self_service", "password"."created_at", "password"."expires_at", "password"."password_hash", "password"."created_at_int", "password"."expires_at_int" FROM "password" WHERE "password"."local_user_id" IN ($1) ORDER BY "password"."created_at_int" DESC"#,
                    []
                ),
            ]) {
            assert_eq!(
                l.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>(),
                r.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]

    async fn test_list_nonlocal_only() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                // local user
                get_user_mock("1"),
                // nonlocal user
                get_user_mock("2"),
                // federated user
                get_user_mock("3"),
                // a "bad" user with no user detail records
                get_user_mock("4"),
            ]])
            .append_query_results([[get_user_options_mock("2", &UserOptions::default())]
                .into_iter()
                .flatten()])
            .append_query_results([vec![get_nonlocal_user_mock("2")]])
            .into_connection();

        let config = Config::default();
        let res = list(
            &config,
            &db,
            &UserListParameters {
                user_type: Some(UserType::NonLocal),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 1, "1 nonlocal user found");

        for (l,r) in db.into_transaction_log().iter().zip([
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" WHERE "user_option"."user_id" IN ($1, $2, $3, $4)"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "nonlocal_user"."domain_id", "nonlocal_user"."name", "nonlocal_user"."user_id" FROM "nonlocal_user" WHERE ("nonlocal_user"."user_id", "nonlocal_user"."domain_id") IN (($1, $2), ($3, $4), ($5, $6), ($7, $8))"#,
                    []
                ),
            ]) {
            assert_eq!(
                l.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>(),
                r.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn test_list_federated_only() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                // local user
                get_user_mock("1"),
                // nonlocal user
                get_user_mock("2"),
                // federated user
                get_user_mock("3"),
                // a "bad" user with no user detail records
                get_user_mock("4"),
            ]])
            .append_query_results([[get_user_options_mock("3", &UserOptions::default())]
                .into_iter()
                .flatten()])
            .append_query_results([vec![get_federated_user_mock("3")]])
            .into_connection();

        let config = Config::default();
        let res = list(
            &config,
            &db,
            &UserListParameters {
                user_type: Some(UserType::Federated),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 1, "1 federated user found");

        for (l,r) in db.into_transaction_log().iter().zip([
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" WHERE "user_option"."user_id" IN ($1, $2, $3, $4)"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_user"."id", "federated_user"."user_id", "federated_user"."idp_id", "federated_user"."protocol_id", "federated_user"."unique_id", "federated_user"."display_name" FROM "federated_user" WHERE "federated_user"."user_id" IN ($1, $2, $3, $4)"#,
                    []
                ),
            ]) {
            assert_eq!(
                l.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>(),
                r.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>()
            );
            }
    }
}
