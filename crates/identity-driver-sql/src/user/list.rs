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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{Condition, Cursor, SelectModel};

use openstack_keystone_config::Config;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::{
    UserListParameters, UserOptions, UserResponse, UserResponseBuilder, UserType,
};

use crate::entity::{
    federated_user as db_federated_user, local_user as db_local_user,
    nonlocal_user as db_nonlocal_user, password as db_password,
    prelude::{FederatedUser, LocalUser, NonlocalUser, User as DbUser, UserOption as DbUserOption},
    user as db_user, user_option as db_user_option,
};
use crate::federated_user::MergeFederatedUserData;
use crate::local_user;
use crate::local_user::MergeLocalUserData;
use crate::nonlocal_user::MergeNonlocalUserData;
use crate::password::MergePasswordData;
use crate::user::MergeUserData;

/// Prepare the paginated query for listing the main `user` rows.
///
/// # Parameters
/// - `params`: The list parameters.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_user_list_query(
    params: &UserListParameters,
) -> Result<Cursor<SelectModel<db_user::Model>>, IdentityProviderError> {
    let mut user_select = DbUser::find();

    if let Some(domain_id) = &params.domain_id {
        user_select = user_select.filter(db_user::Column::DomainId.eq(domain_id));
    }

    let mut cursor = user_select.cursor_by(db_user::Column::Id);
    if let Some(marker) = &params.pagination.marker {
        if params.pagination.page_reverse {
            cursor.before(marker);
        } else {
            cursor.after(marker);
        }
    }
    // Over-fetch by one row so the API layer can tell "there is a
    // next/previous page" exactly, instead of guessing from
    // `returned == limit` (false-positives when exactly `limit` rows
    // remain). `.last()` fetches in descending order but sea-orm returns
    // rows back in ascending order.
    if let Some(limit) = params.pagination.limit {
        if params.pagination.page_reverse {
            cursor.last(limit + 1);
        } else {
            cursor.first(limit + 1);
        }
    }
    Ok(cursor)
}

/// Fetch `local_user`, `nonlocal_user` and `user_option` data for a set of
/// user ids in a single joined query.
///
/// `local_user` and `nonlocal_user` are `has_one` relations of `user` and
/// `user_option` is `has_many`; all three are LEFT JOINed directly off `user`
/// (star topology) and consolidated back into one entry per user id, instead
/// of the three separate `IN (...)`-filtered round-trips this replaces. Only
/// up to 4 entities (root + 3 children) can be consolidated this way with
/// sea-orm's `SelectFourMany`, so `federated_user` (also `has_many`, but
/// needs a 4th slot) and `password` (keyed off `local_user_id`, not
/// `user_id`) stay as separate queries.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_ids`: The user ids to fetch details for.
/// - `name`: Optional name filter, matched against `local_user.name` OR
///   `nonlocal_user.name`.
///
/// # Returns
/// A `Result` containing a map from user id to its `local_user`,
/// `nonlocal_user` and `user_option` rows, or an `Error`.
#[tracing::instrument(skip_all)]
async fn fetch_joined_user_details(
    db: &DatabaseConnection,
    user_ids: &[String],
    name: Option<&str>,
) -> Result<
    HashMap<
        String,
        (
            Vec<db_local_user::Model>,
            Vec<db_nonlocal_user::Model>,
            Vec<db_user_option::Model>,
        ),
    >,
    IdentityProviderError,
> {
    if user_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut select = DbUser::find()
        .filter(db_user::Column::Id.is_in(user_ids))
        .find_also_related(LocalUser)
        .find_also_related(NonlocalUser)
        .find_also(DbUser, DbUserOption);

    if let Some(name) = name {
        select = select.filter(
            Condition::any()
                .add(db_local_user::Column::Name.eq(name))
                .add(db_nonlocal_user::Column::Name.eq(name)),
        );
    }

    // Deliberately not using `.consolidate()`: it decodes every row into a
    // flat `Vec<(user, Option<local>, Option<nonlocal>, Option<option>)>`
    // and then does its own dedup/grouping pass into per-parent `Vec`s. We
    // need our own `HashMap<user_id, _>` regardless (`list()` looks users up
    // by id), so consolidating first and re-grouping from its output would
    // be a second, redundant grouping pass. Group directly off the flat
    // per-row tuples in a single pass instead.
    let rows: Vec<(
        db_user::Model,
        Option<db_local_user::Model>,
        Option<db_nonlocal_user::Model>,
        Option<db_user_option::Model>,
    )> = select
        .all(db)
        .await
        .context("fetching joined local/nonlocal user and user option data")?;

    let mut map: HashMap<
        String,
        (
            Vec<db_local_user::Model>,
            Vec<db_nonlocal_user::Model>,
            Vec<db_user_option::Model>,
        ),
    > = HashMap::new();
    for (u, l, n, o) in rows {
        let entry = map.entry(u.id).or_default();
        // `local`/`nonlocal` are has-one: the same row repeats on every
        // cartesian row produced by the has-many `user_option` join, so only
        // record it once per user instead of pushing a duplicate per row.
        if entry.0.is_empty()
            && let Some(l) = l
        {
            entry.0.push(l);
        }
        if entry.1.is_empty()
            && let Some(n) = n
        {
            entry.1.push(n);
        }
        if let Some(o) = o {
            entry.2.push(o);
        }
    }

    Ok(map)
}

/// List users.
///
/// List users in the database. Fetch matching `user` table entries first.
/// Afterwards fetch, in parallel, `local_user`/`nonlocal_user`/`user_option`
/// (joined in a single query, see [`fetch_joined_user_details`]) and
/// `federated_user`. For the local users additionally passwords are being
/// retrieved to identify the password expiration date.
///
/// # Parameters
/// - `conf`: The system configuration.
/// - `db`: The database connection.
/// - `params`: The list parameters.
///
/// # Returns
/// A `Result` containing a list of `UserResponse`s, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn list(
    conf: &Config,
    db: &DatabaseConnection,
    params: &UserListParameters,
) -> Result<Vec<UserResponse>, IdentityProviderError> {
    let mut federated_user_select = FederatedUser::find();
    if let Some(name) = &params.name {
        federated_user_select =
            federated_user_select.filter(db_federated_user::Column::DisplayName.eq(name));
    }

    // Fetch main `user` entries
    let db_users: Vec<db_user::Model> = get_user_list_query(params)?
        .all(db)
        .await
        .context("fetching users data")?;
    let count_of_users_selected = db_users.len();
    let user_ids: Vec<String> = db_users.iter().map(|u| u.id.clone()).collect();

    let user_type = params.user_type.unwrap_or(UserType::All);
    let (joined, federated_users) = tokio::join!(
        fetch_joined_user_details(db, &user_ids, params.name.as_deref()),
        // Load federated users when requested
        async {
            if user_type == UserType::Federated || user_type == UserType::All {
                db_users.load_many(federated_user_select, db).await
            } else {
                Ok(vec![Vec::new(); count_of_users_selected])
            }
        },
    );
    let joined = joined?;

    let locals: Vec<Option<db_local_user::Model>> = db_users
        .iter()
        .map(|u| joined.get(&u.id).and_then(|(l, _, _)| l.first().cloned()))
        .collect();
    let nonlocals: Vec<Option<db_nonlocal_user::Model>> = db_users
        .iter()
        .map(|u| joined.get(&u.id).and_then(|(_, n, _)| n.first().cloned()))
        .collect();
    let user_opts: Vec<Vec<db_user_option::Model>> = db_users
        .iter()
        .map(|u| {
            joined
                .get(&u.id)
                .map(|(_, _, o)| o.clone())
                .unwrap_or_default()
        })
        .collect();

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
        user_opts.into_iter().zip(
            locals.into_iter().zip(
                local_users_passwords.into_iter().zip(
                    nonlocals.into_iter().zip(
                        federated_users
                            .context("fetching federated users data")?
                            .into_iter(),
                    ),
                ),
            ),
        ),
    ) {
        // The joined query always fetches `local_user`/`nonlocal_user`
        // regardless of `user_type` (unlike `federated_user`, which is only
        // queried when requested), so gate them here to preserve the
        // requested-type filtering.
        let l = l.filter(|_| user_type == UserType::Local || user_type == UserType::All);
        let n = n.filter(|_| user_type == UserType::NonLocal || user_type == UserType::All);

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

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::ListPagination;

    use std::collections::BTreeMap;

    use super::*;
    use crate::entity::password as db_password;
    use crate::federated_user::tests::*;
    use crate::local_user::tests::*;
    use crate::nonlocal_user::tests::*;
    use crate::user::tests::*;

    /// Build a mocked row for the `user`/`local_user`/`nonlocal_user`/
    /// `user_option` joined query, aliasing columns the way sea-orm's
    /// `SelectFourMany` (star topology `consolidate()`) expects: `A_` for
    /// `user`, `B_` for `local_user`, `C_` for `nonlocal_user`. Omitting a
    /// branch's columns entirely (rather than setting them null) mirrors a
    /// LEFT JOIN miss, since `from_query_result_optional` maps any decode
    /// error - including a missing key - to `None`.
    fn mock_join_row(
        user: &db_user::Model,
        local: Option<&db_local_user::Model>,
        nonlocal: Option<&db_nonlocal_user::Model>,
    ) -> BTreeMap<String, sea_orm::Value> {
        let mut row = BTreeMap::new();
        for col in db_user::Column::iter() {
            row.insert(format!("A_{}", col.as_str()), user.get(col));
        }
        if let Some(l) = local {
            for col in db_local_user::Column::iter() {
                row.insert(format!("B_{}", col.as_str()), l.get(col));
            }
        }
        if let Some(n) = nonlocal {
            for col in db_nonlocal_user::Column::iter() {
                row.insert(format!("C_{}", col.as_str()), n.get(col));
            }
        }
        row
    }

    const JOIN_SQL_4_IDS: &str = r#"SELECT "user"."created_at" AS "A_created_at", "user"."default_project_id" AS "A_default_project_id", "user"."domain_id" AS "A_domain_id", "user"."enabled" AS "A_enabled", "user"."extra" AS "A_extra", "user"."id" AS "A_id", "user"."last_active_at" AS "A_last_active_at", "local_user"."id" AS "B_id", "local_user"."user_id" AS "B_user_id", "local_user"."domain_id" AS "B_domain_id", "local_user"."name" AS "B_name", "local_user"."failed_auth_count" AS "B_failed_auth_count", "local_user"."failed_auth_at" AS "B_failed_auth_at", "nonlocal_user"."domain_id" AS "C_domain_id", "nonlocal_user"."name" AS "C_name", "nonlocal_user"."user_id" AS "C_user_id", "user_option"."user_id" AS "D_user_id", "user_option"."option_id" AS "D_option_id", "user_option"."option_value" AS "D_option_value" FROM "user" LEFT JOIN "local_user" ON "user"."id" = "local_user"."user_id" AND "user"."domain_id" = "local_user"."domain_id" LEFT JOIN "nonlocal_user" ON "user"."id" = "nonlocal_user"."user_id" AND "user"."domain_id" = "nonlocal_user"."domain_id" LEFT JOIN "user_option" ON "user"."id" = "user_option"."user_id" WHERE "user"."id" IN ($1, $2, $3, $4)"#;

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
            .append_query_results([vec![
                mock_join_row(&get_user_mock("1"), Some(&get_local_user_mock("1")), None),
                mock_join_row(
                    &get_user_mock("2"),
                    None,
                    Some(&get_nonlocal_user_mock("2")),
                ),
                mock_join_row(&get_user_mock("3"), None, None),
                mock_join_row(&get_user_mock("4"), None, None),
            ]])
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
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user" ORDER BY "user"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    JOIN_SQL_4_IDS,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_user"."id", "federated_user"."user_id", "federated_user"."idp_id", "federated_user"."protocol_id", "federated_user"."unique_id", "federated_user"."display_name" FROM "federated_user" WHERE ("federated_user"."user_id") IN (($1), ($2), ($3), ($4))"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT DISTINCT ON ("local_user_id") "password"."id", "password"."local_user_id", "password"."self_service", "password"."created_at", "password"."expires_at", "password"."password_hash", "password"."created_at_int", "password"."expires_at_int" FROM "password" WHERE "password"."local_user_id" IN ($1) ORDER BY "password"."local_user_id" ASC, "password"."created_at_int" DESC"#,
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
            .append_query_results([vec![
                mock_join_row(&get_user_mock("1"), Some(&get_local_user_mock("1")), None),
                mock_join_row(
                    &get_user_mock("2"),
                    None,
                    Some(&get_nonlocal_user_mock("2")),
                ),
                mock_join_row(&get_user_mock("3"), None, None),
                mock_join_row(&get_user_mock("4"), None, None),
            ]])
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
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user" ORDER BY "user"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    JOIN_SQL_4_IDS,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT DISTINCT ON ("local_user_id") "password"."id", "password"."local_user_id", "password"."self_service", "password"."created_at", "password"."expires_at", "password"."password_hash", "password"."created_at_int", "password"."expires_at_int" FROM "password" WHERE "password"."local_user_id" IN ($1) ORDER BY "password"."local_user_id" ASC, "password"."created_at_int" DESC"#,
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
    async fn test_list_pagination_forward_over_fetches() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Simulates the backend over-fetching `limit + 1 == 2` rows.
            .append_query_results([vec![get_user_mock("1"), get_user_mock("2")]])
            .append_query_results([vec![
                mock_join_row(&get_user_mock("1"), Some(&get_local_user_mock("1")), None),
                mock_join_row(&get_user_mock("2"), Some(&get_local_user_mock("2")), None),
            ]])
            .append_query_results([Vec::<db_password::Model>::new()])
            .into_connection();

        let config = Config::default();
        let res = list(
            &config,
            &db,
            &UserListParameters {
                user_type: Some(UserType::Local),
                pagination: ListPagination {
                    limit: Some(1),
                    marker: Some("m".into()),
                    page_reverse: false,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""user"."id" >"#));
        assert!(sql.contains(r#"ORDER BY "user"."id" ASC"#));
        assert!(sql.contains("LIMIT"));
    }

    #[tokio::test]
    async fn test_list_page_reverse() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_mock("2"), get_user_mock("3")]])
            .append_query_results([vec![
                mock_join_row(&get_user_mock("2"), Some(&get_local_user_mock("2")), None),
                mock_join_row(&get_user_mock("3"), Some(&get_local_user_mock("3")), None),
            ]])
            .append_query_results([Vec::<db_password::Model>::new()])
            .into_connection();

        let config = Config::default();
        let res = list(
            &config,
            &db,
            &UserListParameters {
                user_type: Some(UserType::Local),
                pagination: ListPagination {
                    limit: Some(1),
                    marker: Some("m".into()),
                    page_reverse: true,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 2);

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""user"."id" <"#));
        assert!(
            sql.contains(r#"ORDER BY "user"."id" DESC"#),
            "expected DESC fetch direction for page_reverse: {sql}"
        );
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
            .append_query_results([vec![
                mock_join_row(&get_user_mock("1"), Some(&get_local_user_mock("1")), None),
                mock_join_row(
                    &get_user_mock("2"),
                    None,
                    Some(&get_nonlocal_user_mock("2")),
                ),
                mock_join_row(&get_user_mock("3"), None, None),
                mock_join_row(&get_user_mock("4"), None, None),
            ]])
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
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user" ORDER BY "user"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    JOIN_SQL_4_IDS,
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
            .append_query_results([vec![
                mock_join_row(&get_user_mock("1"), Some(&get_local_user_mock("1")), None),
                mock_join_row(
                    &get_user_mock("2"),
                    None,
                    Some(&get_nonlocal_user_mock("2")),
                ),
                mock_join_row(&get_user_mock("3"), None, None),
                mock_join_row(&get_user_mock("4"), None, None),
            ]])
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
                    r#"SELECT "user"."created_at", "user"."default_project_id", "user"."domain_id", "user"."enabled", "user"."extra", "user"."id", "user"."last_active_at" FROM "user" ORDER BY "user"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    JOIN_SQL_4_IDS,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_user"."id", "federated_user"."user_id", "federated_user"."idp_id", "federated_user"."protocol_id", "federated_user"."unique_id", "federated_user"."display_name" FROM "federated_user" WHERE ("federated_user"."user_id") IN (($1), ($2), ($3), ($4))"#,
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
