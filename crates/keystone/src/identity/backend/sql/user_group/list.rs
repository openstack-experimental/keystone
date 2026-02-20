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
use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::sea_query::*;

use crate::db::entity::{
    expiring_user_group_membership, group as db_group, prelude::Group as DbGroup,
    user_group_membership,
};
use crate::error::DbContextExt;
use crate::identity::{IdentityProviderError, types::Group};

/// List all groups the user is member of.
///
/// Selects all groups with the ID in the list of user group memberships and
/// expiring group memberships.
#[tracing::instrument(skip_all)]
pub async fn list_user_groups<S: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: S,
    last_verified_cutof: &DateTime<Utc>,
) -> Result<Vec<Group>, IdentityProviderError> {
    let groups: Vec<Group> = DbGroup::find()
        .filter(
            db_group::Column::Id.in_subquery(
                Query::select()
                    .column(user_group_membership::Column::GroupId)
                    .from(user_group_membership::Entity)
                    .and_where(user_group_membership::Column::UserId.eq(user_id.as_ref()))
                    .union(
                        UnionType::All,
                        Query::select()
                            .column(expiring_user_group_membership::Column::GroupId)
                            .from(expiring_user_group_membership::Entity)
                            .and_where(
                                expiring_user_group_membership::Column::UserId.eq(user_id.as_ref()),
                            )
                            .and_where(
                                expiring_user_group_membership::Column::LastVerified
                                    .gt(last_verified_cutof.naive_utc()),
                            )
                            .to_owned(),
                    )
                    .to_owned(),
            ),
        )
        .distinct()
        .all(db)
        .await
        .context("listing groups the user is currently in")?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;
    use crate::config::Config;
    use crate::identity::backend::sql::group::tests::get_group_mock;

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1"), get_group_mock("2")]])
            .into_connection();
        let expiring_datetime = Config::default()
            .federation
            .get_expiring_user_group_membership_cutof_datetime();
        assert_eq!(
            list_user_groups(&db, "foo", &expiring_datetime)
                .await
                .unwrap(),
            vec![get_group_mock("1").into(), get_group_mock("2").into()]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT DISTINCT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" WHERE "group"."id" IN (SELECT "group_id" FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1 UNION ALL (SELECT "group_id" FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $2 AND "expiring_user_group_membership"."last_verified" > $3))"#,
                [
                    "foo".into(),
                    "foo".into(),
                    expiring_datetime.naive_utc().into()
                ]
            ),]
        );
    }
}
