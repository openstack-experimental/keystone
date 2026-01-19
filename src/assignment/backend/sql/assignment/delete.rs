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

use sea_orm::entity::*;
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter};

use crate::assignment::backend::error::AssignmentDatabaseError;
use crate::assignment::types::*;
use crate::db::entity::{
    assignment as db_assignment, sea_orm_active_enums::Type as DbAssignmentType,
    system_assignment as db_system_assignment,
};
use crate::error::DbContextExt;

/// Delete assignment grant.
pub async fn delete(
    db: &DatabaseConnection,
    grant: &AssignmentRevoke,
) -> Result<(), AssignmentDatabaseError> {
    if grant.inherited {
        // Cannot delete inherited assignments directly
        return Ok(());
    }

    match &grant.r#type {
        AssignmentType::GroupDomain
        | AssignmentType::GroupProject
        | AssignmentType::UserDomain
        | AssignmentType::UserProject => {
            db_assignment::Entity::delete_many()
                .filter(db_assignment::Column::RoleId.eq(&grant.role_id))
                .filter(db_assignment::Column::TargetId.eq(&grant.target_id))
                .filter(db_assignment::Column::ActorId.eq(&grant.actor_id))
                .filter(db_assignment::Column::Type.eq(DbAssignmentType::try_from(&grant.r#type)?))
                .filter(db_assignment::Column::Inherited.eq(false))
                .exec(db)
                .await
                .context("deleting assignment")?;
        }
        AssignmentType::GroupSystem | AssignmentType::UserSystem => {
            db_system_assignment::Entity::delete_many()
                .filter(db_system_assignment::Column::RoleId.eq(&grant.role_id))
                .filter(db_system_assignment::Column::TargetId.eq(&grant.target_id))
                .filter(db_system_assignment::Column::ActorId.eq(&grant.actor_id))
                .filter(db_system_assignment::Column::Type.eq(grant.r#type.to_string()))
                .filter(db_system_assignment::Column::Inherited.eq(false))
                .exec(db)
                .await
                .context("deleting system assignment")?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_delete_user_project() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1, // 1 row deleted
            }])
            .into_connection();

        let grant = AssignmentRevoke {
            role_id: "role_id".into(),
            actor_id: "actor_id".into(),
            target_id: "target_id".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
        };

        delete(&db, &grant).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."target_id" = $2 AND "assignment"."actor_id" = $3 AND "assignment"."type" = (CAST($4 AS "type")) AND "assignment"."inherited" = $5"#,
                [
                    "role_id".into(),
                    "target_id".into(),
                    "actor_id".into(),
                    "UserProject".into(),
                    false.into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_group_project() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let grant = AssignmentRevoke {
            role_id: "role_id".into(),
            actor_id: "group_id".into(),
            target_id: "project_id".into(),
            r#type: AssignmentType::GroupProject,
            inherited: false,
        };

        delete(&db, &grant).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."target_id" = $2 AND "assignment"."actor_id" = $3 AND "assignment"."type" = (CAST($4 AS "type")) AND "assignment"."inherited" = $5"#,
                [
                    "role_id".into(),
                    "project_id".into(),
                    "group_id".into(),
                    "GroupProject".into(),
                    false.into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_user_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let grant = AssignmentRevoke {
            role_id: "role_id".into(),
            actor_id: "user_id".into(),
            target_id: "domain_id".into(),
            r#type: AssignmentType::UserDomain,
            inherited: false,
        };

        delete(&db, &grant).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."target_id" = $2 AND "assignment"."actor_id" = $3 AND "assignment"."type" = (CAST($4 AS "type")) AND "assignment"."inherited" = $5"#,
                [
                    "role_id".into(),
                    "domain_id".into(),
                    "user_id".into(),
                    "UserDomain".into(),
                    false.into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_user_system() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let grant = AssignmentRevoke {
            role_id: "role_id".into(),
            actor_id: "user_id".into(),
            target_id: "system".into(),
            r#type: AssignmentType::UserSystem,
            inherited: false,
        };

        delete(&db, &grant).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "system_assignment" WHERE "system_assignment"."role_id" = $1 AND "system_assignment"."target_id" = $2 AND "system_assignment"."actor_id" = $3 AND "system_assignment"."type" = $4 AND "system_assignment"."inherited" = $5"#,
                [
                    "role_id".into(),
                    "system".into(),
                    "user_id".into(),
                    "UserSystem".into(),
                    false.into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_group_system() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let grant = AssignmentRevoke {
            role_id: "role_id".into(),
            actor_id: "group_id".into(),
            target_id: "system".into(),
            r#type: AssignmentType::GroupSystem,
            inherited: false,
        };

        delete(&db, &grant).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "system_assignment" WHERE "system_assignment"."role_id" = $1 AND "system_assignment"."target_id" = $2 AND "system_assignment"."actor_id" = $3 AND "system_assignment"."type" = $4 AND "system_assignment"."inherited" = $5"#,
                [
                    "role_id".into(),
                    "system".into(),
                    "group_id".into(),
                    "GroupSystem".into(),
                    false.into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_inherited_succeeds_without_deletion() {
        // Inherited grants should be silently skipped
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

        let grant = AssignmentRevoke {
            role_id: "role_id".into(),
            actor_id: "user_id".into(),
            target_id: "project_id".into(),
            r#type: AssignmentType::UserProject,
            inherited: true, // ← Inherited
        };

        delete(&db, &grant).await.unwrap();

        // No SQL should be executed for inherited grants
        assert_eq!(db.into_transaction_log(), []);
    }

    #[tokio::test]
    async fn test_delete_not_found_succeeds() {
        // Deleting non-existent grant should succeed (idempotent)
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 0, // ← 0 rows deleted
            }])
            .into_connection();

        let grant = AssignmentRevoke {
            role_id: "nonexistent_role".into(),
            actor_id: "user_id".into(),
            target_id: "project_id".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
        };

        // Should succeed even though nothing was deleted
        delete(&db, &grant).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."target_id" = $2 AND "assignment"."actor_id" = $3 AND "assignment"."type" = (CAST($4 AS "type")) AND "assignment"."inherited" = $5"#,
                [
                    "nonexistent_role".into(),
                    "project_id".into(),
                    "user_id".into(),
                    "UserProject".into(),
                    false.into(),
                ]
            ),]
        );
    }
}
