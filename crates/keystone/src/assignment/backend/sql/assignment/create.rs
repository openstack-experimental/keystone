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

use crate::assignment::backend::error::AssignmentDatabaseError;
use crate::assignment::types::*;
use crate::db::entity::{
    assignment as db_assignment, sea_orm_active_enums::Type as DbAssignmentType,
    system_assignment as db_system_assignment,
};
use crate::error::DbContextExt;

/// Create assignment grant.
pub async fn create(
    db: &DatabaseConnection,
    assignment: AssignmentCreate,
) -> Result<Assignment, AssignmentDatabaseError> {
    match assignment.r#type {
        AssignmentType::GroupDomain
        | AssignmentType::GroupProject
        | AssignmentType::UserDomain
        | AssignmentType::UserProject => Ok(Assignment::from(
            db_assignment::ActiveModel {
                r#type: Set(DbAssignmentType::try_from(&assignment.r#type)?),
                role_id: Set(assignment.role_id),
                actor_id: Set(assignment.actor_id),
                target_id: Set(assignment.target_id),
                inherited: Set(assignment.inherited),
            }
            .insert(db)
            .await
            .context("persisting assignment")?,
        )),
        other => Assignment::try_from(
            db_system_assignment::ActiveModel {
                r#type: Set(other.to_string()),
                role_id: Set(assignment.role_id),
                actor_id: Set(assignment.actor_id),
                target_id: Set(assignment.target_id),
                inherited: Set(assignment.inherited),
            }
            .insert(db)
            .await
            .context("persisting system assignment")?,
        ),
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("role_id")]])
            .into_connection();
        assert_eq!(
            create(
                &db,
                AssignmentCreate {
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
            Assignment {
                role_id: "role_id".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: AssignmentType::UserProject,
                inherited: false,
                implied_via: None,
            }
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "assignment" ("type", "actor_id", "target_id", "role_id", "inherited") VALUES (CAST($1 AS "type"), $2, $3, $4, $5) RETURNING CAST("type" AS "text"), "actor_id", "target_id", "role_id", "inherited""#,
                [
                    "UserProject".into(),
                    "actor_id".into(),
                    "target_id".into(),
                    "role_id".into(),
                    true.into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_create_system_user() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("role_id")]])
            .into_connection();
        create(
            &db,
            AssignmentCreate {
                role_id: "role_id".into(),
                role_name: None,
                actor_id: "actor_id".into(),
                target_id: "target_id".into(),
                r#type: AssignmentType::UserSystem,
                inherited: true,
            },
        )
        .await
        .unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "system_assignment" ("type", "actor_id", "target_id", "role_id", "inherited") VALUES ($1, $2, $3, $4, $5) RETURNING "type", "actor_id", "target_id", "role_id", "inherited""#,
                [
                    "UserSystem".into(),
                    "actor_id".into(),
                    "target_id".into(),
                    "role_id".into(),
                    true.into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_create_system_group() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("role_id")]])
            .into_connection();
        create(
            &db,
            AssignmentCreate {
                role_id: "role_id".into(),
                role_name: None,
                actor_id: "actor_id".into(),
                target_id: "target_id".into(),
                r#type: AssignmentType::GroupSystem,
                inherited: true,
            },
        )
        .await
        .unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "system_assignment" ("type", "actor_id", "target_id", "role_id", "inherited") VALUES ($1, $2, $3, $4, $5) RETURNING "type", "actor_id", "target_id", "role_id", "inherited""#,
                [
                    "GroupSystem".into(),
                    "actor_id".into(),
                    "target_id".into(),
                    "role_id".into(),
                    true.into(),
                ]
            ),]
        );
    }
}
