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
//! Check grant presence.

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use crate::assignment::backend::error::AssignmentDatabaseError;
use crate::assignment::types::*;
use crate::db::entity::{
    assignment as db_assignment,
    prelude::{Assignment as DbAssignment, SystemAssignment as DbSystemAssignment},
    sea_orm_active_enums::Type as DbAssignmentType,
    system_assignment as db_system_assignment,
};
use crate::error::DbContextExt;

/// Check whether the grant exists.
///
/// # Result
///
/// * `Ok(true)` when the grant is present.
/// * `Ok(false)` when the grant does not exist
pub async fn check(
    db: &DatabaseConnection,
    grant: &Assignment,
) -> Result<bool, AssignmentDatabaseError> {
    let count: u64 = match &grant.r#type {
        t @ AssignmentType::GroupDomain
        | t @ AssignmentType::GroupProject
        | t @ AssignmentType::UserDomain
        | t @ AssignmentType::UserProject => DbAssignment::find()
            .filter(db_assignment::Column::RoleId.eq(grant.role_id.as_str()))
            .filter(db_assignment::Column::TargetId.eq(grant.target_id.as_str()))
            .filter(db_assignment::Column::ActorId.eq(grant.actor_id.as_str()))
            .filter(db_assignment::Column::Type.eq(DbAssignmentType::try_from(t)?))
            .filter(db_assignment::Column::Inherited.eq(grant.inherited))
            .count(db)
            .await
            .context("checking grant")?,
        t @ AssignmentType::GroupSystem | t @ AssignmentType::UserSystem => {
            DbSystemAssignment::find()
                .filter(db_system_assignment::Column::RoleId.eq(grant.role_id.as_str()))
                .filter(db_system_assignment::Column::TargetId.eq(grant.target_id.as_str()))
                .filter(db_system_assignment::Column::ActorId.eq(grant.actor_id.as_str()))
                .filter(db_system_assignment::Column::Type.eq(t.to_string()))
                .filter(db_system_assignment::Column::Inherited.eq(grant.inherited))
                .count(db)
                .await
                .context("checking system grant")?
        }
    };
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, Transaction};
    use std::collections::BTreeMap;

    use super::*;

    #[tokio::test]
    async fn test_check() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                BTreeMap::from([("num_items", Into::<Value>::into(1i64))]).into_mock_row(),
            ]])
            .append_query_results([vec![
                BTreeMap::from([("num_items", Into::<Value>::into(0i64))]).into_mock_row(),
            ]])
            .into_connection();
        assert!(
            check(
                &db,
                &Assignment {
                    role_id: "role_id".into(),
                    role_name: None,
                    actor_id: "actor_id".into(),
                    target_id: "target_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: true
                }
            )
            .await
            .unwrap(),
        );
        assert!(
            !check(
                &db,
                &Assignment {
                    role_id: "role_id2".into(),
                    role_name: None,
                    actor_id: "actor_id".into(),
                    target_id: "target_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: true
                }
            )
            .await
            .unwrap(),
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT COUNT(*) AS num_items FROM (SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."target_id" = $2 AND "assignment"."actor_id" = $3 AND "assignment"."type" = (CAST($4 AS "type")) AND "assignment"."inherited" = $5) AS "sub_query""#,
                    [
                        "role_id".into(),
                        "target_id".into(),
                        "actor_id".into(),
                        "UserProject".into(),
                        true.into(),
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT COUNT(*) AS num_items FROM (SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."target_id" = $2 AND "assignment"."actor_id" = $3 AND "assignment"."type" = (CAST($4 AS "type")) AND "assignment"."inherited" = $5) AS "sub_query""#,
                    [
                        "role_id2".into(),
                        "target_id".into(),
                        "actor_id".into(),
                        "UserProject".into(),
                        true.into(),
                    ]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_check_system() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                BTreeMap::from([("num_items", Into::<Value>::into(1i64))]).into_mock_row(),
            ]])
            .append_query_results([vec![
                BTreeMap::from([("num_items", Into::<Value>::into(0i64))]).into_mock_row(),
            ]])
            .into_connection();
        assert!(
            check(
                &db,
                &Assignment {
                    role_id: "role_id".into(),
                    role_name: None,
                    actor_id: "actor_id".into(),
                    target_id: "target_id".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: true
                }
            )
            .await
            .unwrap(),
        );
        assert!(
            !check(
                &db,
                &Assignment {
                    role_id: "role_id2".into(),
                    role_name: None,
                    actor_id: "actor_id".into(),
                    target_id: "target_id".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: true
                }
            )
            .await
            .unwrap(),
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT COUNT(*) AS num_items FROM (SELECT "system_assignment"."type", "system_assignment"."actor_id", "system_assignment"."target_id", "system_assignment"."role_id", "system_assignment"."inherited" FROM "system_assignment" WHERE "system_assignment"."role_id" = $1 AND "system_assignment"."target_id" = $2 AND "system_assignment"."actor_id" = $3 AND "system_assignment"."type" = $4 AND "system_assignment"."inherited" = $5) AS "sub_query""#,
                    [
                        "role_id".into(),
                        "target_id".into(),
                        "actor_id".into(),
                        "UserSystem".into(),
                        true.into(),
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT COUNT(*) AS num_items FROM (SELECT "system_assignment"."type", "system_assignment"."actor_id", "system_assignment"."target_id", "system_assignment"."role_id", "system_assignment"."inherited" FROM "system_assignment" WHERE "system_assignment"."role_id" = $1 AND "system_assignment"."target_id" = $2 AND "system_assignment"."actor_id" = $3 AND "system_assignment"."type" = $4 AND "system_assignment"."inherited" = $5) AS "sub_query""#,
                    [
                        "role_id2".into(),
                        "target_id".into(),
                        "actor_id".into(),
                        "UserSystem".into(),
                        true.into(),
                    ]
                ),
            ]
        );
    }
}
