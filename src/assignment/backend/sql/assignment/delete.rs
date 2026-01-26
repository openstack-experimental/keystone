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
use sea_orm::{DatabaseConnection, EntityTrait};

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
    grant: Assignment,
) -> Result<(), AssignmentDatabaseError> {
    let rows_affected = match &grant.r#type {
        AssignmentType::GroupDomain
        | AssignmentType::GroupProject
        | AssignmentType::UserDomain
        | AssignmentType::UserProject => {
            let pk = (
                DbAssignmentType::try_from(&grant.r#type)?,
                grant.actor_id.clone(),
                grant.target_id.clone(),
                grant.role_id.clone(),
                grant.inherited,
            );

            db_assignment::Entity::delete_by_id(pk)
                .exec(db)
                .await
                .context("deleting assignment by pk")?
                .rows_affected
        }
        AssignmentType::GroupSystem | AssignmentType::UserSystem => {
            let pk = (
                grant.r#type.to_string(), // This might need to be different too
                grant.actor_id.clone(),
                grant.target_id.clone(),
                grant.role_id.clone(),
                grant.inherited,
            );

            db_system_assignment::Entity::delete_by_id(pk)
                .exec(db)
                .await
                .context("deleting system assignment")?
                .rows_affected
        }
    };

    if rows_affected == 0 {
        return Err(AssignmentDatabaseError::AssignmentNotFound(format!(
            "actor={}, target={}, role={}, type={:?}, inherited={}",
            grant.actor_id, grant.target_id, grant.role_id, grant.r#type, grant.inherited
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_delete_user_project_success() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1, // 1 row deleted
            }])
            .into_connection();

        let grant = Assignment {
            role_id: "role_id".into(),
            actor_id: "actor_id".into(),
            target_id: "target_id".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            role_name: None,
            implied_via: None,
        };

        // Should succeed
        delete(&db, grant).await.unwrap();

        // Verify SQL was executed correctly
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
    async fn test_delete_group_project_success() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let grant = Assignment {
            role_id: "role_id".into(),
            actor_id: "group_id".into(),
            target_id: "project_id".into(),
            r#type: AssignmentType::GroupProject,
            inherited: false,
            role_name: None,
            implied_via: None,
        };

        delete(&db, grant).await.unwrap();

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
    async fn test_delete_user_domain_success() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let grant = Assignment {
            role_id: "role_id".into(),
            actor_id: "user_id".into(),
            target_id: "domain_id".into(),
            r#type: AssignmentType::UserDomain,
            inherited: false,
            role_name: None,
            implied_via: None,
        };

        delete(&db, grant).await.unwrap();

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
    async fn test_delete_user_system_success() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let grant = Assignment {
            role_id: "role_id".into(),
            actor_id: "user_id".into(),
            target_id: "system".into(),
            r#type: AssignmentType::UserSystem,
            inherited: false,
            role_name: None,
            implied_via: None,
        };

        delete(&db, grant).await.unwrap();

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
    async fn test_delete_group_system_success() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let grant = Assignment {
            role_id: "role_id".into(),
            actor_id: "group_id".into(),
            target_id: "system".into(),
            r#type: AssignmentType::GroupSystem,
            inherited: false,
            role_name: None,
            implied_via: None,
        };

        delete(&db, grant).await.unwrap();

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
    async fn test_delete_inherited_assignment_success() {
        // Inherited assignments CAN now be deleted (if they exist in DB)
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1, // ← 1 row deleted
            }])
            .into_connection();

        let grant = Assignment {
            role_id: "role_id".into(),
            actor_id: "user_id".into(),
            target_id: "project_id".into(),
            r#type: AssignmentType::UserProject,
            inherited: true, // ← Inherited assignment
            role_name: None,
            implied_via: None,
        };

        // Should succeed
        delete(&db, grant).await.unwrap();

        // Verify correct SQL with inherited=true
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "assignment" WHERE "assignment"."role_id" = $1 AND "assignment"."target_id" = $2 AND "assignment"."actor_id" = $3 AND "assignment"."type" = (CAST($4 AS "type")) AND "assignment"."inherited" = $5"#,
                [
                    "role_id".into(),
                    "project_id".into(),
                    "user_id".into(),
                    "UserProject".into(),
                    true.into(), // ← inherited=true
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_not_found_returns_error() {
        // Deleting non-existent grant should return AssignmentNotFound error
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 0, // ← 0 rows deleted
            }])
            .into_connection();

        let grant = Assignment {
            role_id: "nonexistent_role".into(),
            actor_id: "user_id".into(),
            target_id: "project_id".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            role_name: None,
            implied_via: None,
        };

        // Should return error
        let result = delete(&db, grant).await;

        assert!(result.is_err());

        // Verify it's the correct error type
        match result {
            Err(AssignmentDatabaseError::AssignmentNotFound(msg)) => {
                assert!(msg.contains("nonexistent_role"));
                assert!(msg.contains("user_id"));
                assert!(msg.contains("project_id"));
            }
            _ => panic!("Expected AssignmentNotFound error, got: {:?}", result),
        }

        // Verify SQL was still executed
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
