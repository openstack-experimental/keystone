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
use sea_orm::{Cursor, SelectModel};
use sea_orm::{FromQueryResult, JoinType, RelationTrait};

use super::super::user_option;
use crate::config::Config;
use crate::db::entity::{
    nonlocal_user as db_nonlocal_user, prelude::User as DbUser, user as db_user,
    user_option as db_user_option,
};
use crate::error::DbContextExt;
use crate::identity::backend::error::IdentityDatabaseError;
use crate::identity::types::*;

#[derive(Debug, FromQueryResult, PartialEq)]
pub struct DbServiceAccount {
    pub id: String,
    pub domain_id: String,
    pub enabled: bool,
    pub name: String,
}

fn build_query(
    params: &ServiceAccountListParameters,
) -> Result<Cursor<SelectModel<DbServiceAccount>>, IdentityDatabaseError> {
    let mut cursor = DbUser::find()
        .select_only()
        .column(db_user::Column::Id)
        .column(db_user::Column::DomainId)
        .column(db_user::Column::Enabled)
        .column(db_nonlocal_user::Column::Name)
        .join(
            JoinType::InnerJoin,
            db_user::Relation::UserOption
                .def()
                .on_condition(|_left, _right| {
                    Condition::all()
                        .add(
                            db_user_option::Column::OptionId
                                .eq(user_option::UserOption::IsServiceAccount.to_string()),
                        )
                        .add(db_user_option::Column::OptionValue.eq("true"))
                }),
        )
        .join(JoinType::InnerJoin, db_user::Relation::NonlocalUser.def())
        .filter(
            Condition::all()
                .add_option(
                    params
                        .domain_id
                        .as_ref()
                        .map(|domain| db_user::Column::DomainId.eq(domain)),
                )
                .add_option(
                    params
                        .name
                        .as_ref()
                        .map(|name| db_nonlocal_user::Column::Name.eq(name)),
                ),
        )
        .cursor_by(db_user::Column::Id);

    if let Some(limit) = params.limit {
        cursor.first(limit);
    }
    if let Some(marker) = &params.marker {
        cursor.after(marker);
    }
    Ok(cursor.into_model())
}

/// List service accounts.
///
/// List service accounts in the database.
#[tracing::instrument(skip_all)]
pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &ServiceAccountListParameters,
) -> Result<Vec<ServiceAccount>, IdentityDatabaseError> {
    Ok(build_query(params)?
        .all(db)
        .await
        .context("listing service accounts")?
        .into_iter()
        .map(|value| ServiceAccount {
            id: value.id,
            domain_id: value.domain_id,
            enabled: value.enabled,
            name: value.name,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use sea_orm::{
        DatabaseBackend, IntoMockRow, MockDatabase, QueryOrder, Transaction, sea_query::*,
    };
    use std::collections::BTreeMap;

    use crate::config::Config;

    use super::*;

    #[test]
    fn test_build_query_default() {
        assert_eq!(
            "SELECT \"user\".\"id\", \"user\".\"domain_id\", \"user\".\"enabled\", \"nonlocal_user\".\"name\" FROM \"user\" INNER JOIN \"user_option\" ON \"user\".\"id\" = \"user_option\".\"user_id\" AND (\"user_option\".\"option_id\" = 'ISSA' AND \"user_option\".\"option_value\" = 'true') INNER JOIN \"nonlocal_user\" ON \"user\".\"id\" = \"nonlocal_user\".\"user_id\" AND \"user\".\"domain_id\" = \"nonlocal_user\".\"domain_id\" WHERE TRUE",
            QueryOrder::query(&mut build_query(&ServiceAccountListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[test]
    fn test_build_query_domain_id() {
        assert_eq!(
            "SELECT \"user\".\"id\", \"user\".\"domain_id\", \"user\".\"enabled\", \"nonlocal_user\".\"name\" FROM \"user\" INNER JOIN \"user_option\" ON \"user\".\"id\" = \"user_option\".\"user_id\" AND (\"user_option\".\"option_id\" = 'ISSA' AND \"user_option\".\"option_value\" = 'true') INNER JOIN \"nonlocal_user\" ON \"user\".\"id\" = \"nonlocal_user\".\"user_id\" AND \"user\".\"domain_id\" = \"nonlocal_user\".\"domain_id\" WHERE \"user\".\"domain_id\" = 'did'",
            QueryOrder::query(
                &mut build_query(&ServiceAccountListParameters {
                    domain_id: Some("did".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
        );
    }

    #[test]
    fn test_build_query_name() {
        assert_eq!(
            "SELECT \"user\".\"id\", \"user\".\"domain_id\", \"user\".\"enabled\", \"nonlocal_user\".\"name\" FROM \"user\" INNER JOIN \"user_option\" ON \"user\".\"id\" = \"user_option\".\"user_id\" AND (\"user_option\".\"option_id\" = 'ISSA' AND \"user_option\".\"option_value\" = 'true') INNER JOIN \"nonlocal_user\" ON \"user\".\"id\" = \"nonlocal_user\".\"user_id\" AND \"user\".\"domain_id\" = \"nonlocal_user\".\"domain_id\" WHERE \"nonlocal_user\".\"name\" = 'sa_name'",
            QueryOrder::query(
                &mut build_query(&ServiceAccountListParameters {
                    name: Some("sa_name".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
        );
    }
    #[test]
    fn test_build_query_all() {
        assert_eq!(
            "SELECT \"user\".\"id\", \"user\".\"domain_id\", \"user\".\"enabled\", \"nonlocal_user\".\"name\" FROM \"user\" INNER JOIN \"user_option\" ON \"user\".\"id\" = \"user_option\".\"user_id\" AND (\"user_option\".\"option_id\" = 'ISSA' AND \"user_option\".\"option_value\" = 'true') INNER JOIN \"nonlocal_user\" ON \"user\".\"id\" = \"nonlocal_user\".\"user_id\" AND \"user\".\"domain_id\" = \"nonlocal_user\".\"domain_id\" WHERE \"user\".\"domain_id\" = 'did' AND \"nonlocal_user\".\"name\" = 'sa_name'",
            QueryOrder::query(
                &mut build_query(&ServiceAccountListParameters {
                    domain_id: Some("did".into()),
                    name: Some("sa_name".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                BTreeMap::from([
                    ("id", Into::<Value>::into("uid1")),
                    ("domain_id", Into::<Value>::into("did")),
                    ("enabled", Into::<Value>::into(true)),
                    ("name", Into::<Value>::into("sa_1")),
                ])
                .into_mock_row(),
                BTreeMap::from([
                    ("id", Into::<Value>::into("uid2")),
                    ("domain_id", Into::<Value>::into("did")),
                    ("enabled", Into::<Value>::into(false)),
                    ("name", Into::<Value>::into("sa_2")),
                ])
                .into_mock_row(),
            ]])
            .into_connection();

        let config = Config::default();
        let res = list(
            &config,
            &db,
            &ServiceAccountListParameters {
                domain_id: Some("did".into()),
                name: Some("name".into()),
                limit: Some(5),
                marker: Some("marker".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(2, res.len());
        assert!(res.contains(&ServiceAccount {
            id: "uid1".into(),
            domain_id: "did".into(),
            enabled: true,
            name: "sa_1".into()
        }));
        assert!(res.contains(&ServiceAccount {
            id: "uid2".into(),
            domain_id: "did".into(),
            enabled: false,
            name: "sa_2".into()
        }));

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user"."id", "user"."domain_id", "user"."enabled", "nonlocal_user"."name" FROM "user" INNER JOIN "user_option" ON "user"."id" = "user_option"."user_id" AND ("user_option"."option_id" = $1 AND "user_option"."option_value" = $2) INNER JOIN "nonlocal_user" ON "user"."id" = "nonlocal_user"."user_id" AND "user"."domain_id" = "nonlocal_user"."domain_id" WHERE "user"."domain_id" = $3 AND "nonlocal_user"."name" = $4 AND "user"."id" > $5 ORDER BY "user"."id" ASC LIMIT $6"#,
                [
                    "ISSA".into(),
                    "true".into(),
                    "did".into(),
                    "name".into(),
                    "marker".into(),
                    5u64.into()
                ]
            ),]
        );
    }
}
