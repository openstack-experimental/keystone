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
use sea_orm::prelude::Expr;
use sea_orm::query::*;
use std::collections::{BTreeMap, HashMap};

use crate::assignment::backend::error::{AssignmentDatabaseError, db_err};
use crate::assignment::backend::sql::implied_role;
use crate::assignment::types::*;
use crate::config::Config;
use crate::db::entity::{
    assignment as db_assignment,
    prelude::{Assignment as DbAssignment, Role as DbRole, SystemAssignment as DbSystemAssignment},
    role as db_role,
    sea_orm_active_enums::Type as DbAssignmentType,
    system_assignment as db_system_assignment,
};

pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &RoleAssignmentListParameters,
) -> Result<Vec<Assignment>, AssignmentDatabaseError> {
    let mut select_assignment = DbAssignment::find();
    let mut select_system_assignment = DbSystemAssignment::find();

    if let Some(val) = &params.role_id {
        select_assignment = select_assignment.filter(db_assignment::Column::RoleId.eq(val));
        select_system_assignment =
            select_system_assignment.filter(db_system_assignment::Column::RoleId.eq(val));
    }
    if let Some(val) = &params.user_id {
        select_assignment = select_assignment.filter(db_assignment::Column::ActorId.eq(val));
        select_system_assignment =
            select_system_assignment.filter(db_system_assignment::Column::ActorId.eq(val));
    } else if let Some(val) = &params.group_id {
        select_assignment = select_assignment.filter(db_assignment::Column::ActorId.eq(val));
        select_system_assignment =
            select_system_assignment.filter(db_system_assignment::Column::ActorId.eq(val));
    }
    if let Some(val) = &params.project_id {
        select_assignment = select_assignment
            .filter(db_assignment::Column::TargetId.eq(val))
            .filter(db_assignment::Column::Type.is_in([
                DbAssignmentType::UserProject,
                DbAssignmentType::GroupProject,
            ]))
            .filter(db_assignment::Column::Inherited.eq(false));
    } else if let Some(val) = &params.domain_id {
        select_assignment = select_assignment
            .filter(db_assignment::Column::TargetId.eq(val))
            .filter(
                db_assignment::Column::Type
                    .is_in([DbAssignmentType::UserDomain, DbAssignmentType::GroupDomain]),
            )
            .filter(db_assignment::Column::Inherited.eq(false));
    } else {
        select_system_assignment = select_system_assignment
            .filter(db_system_assignment::Column::TargetId.eq("system"))
            .filter(db_system_assignment::Column::Inherited.eq(false));
    }

    let results: Result<Vec<Assignment>, _> = if let Some(true) = &params.include_names {
        let db_assignments: Vec<(db_assignment::Model, Option<db_role::Model>)> = select_assignment
            .find_also_related(DbRole)
            .all(db)
            .await
            .map_err(|err| db_err(err, "fetching role assignments with roles"))?;
        let db_system_assignments: Vec<(db_system_assignment::Model, Option<db_role::Model>)> =
            if params.project_id.is_none() && params.domain_id.is_none() {
                // get system scope assignments only when no project or domain is specified
                select_system_assignment
                    .find_also_related(DbRole)
                    .all(db)
                    .await
                    .map_err(|err| db_err(err, "fetching system role assignments with roles"))?
            } else {
                Vec::new()
            };
        db_assignments
            .into_iter()
            .map(|item| TryInto::<Assignment>::try_into((item.0, item.1)))
            .chain(
                db_system_assignments
                    .into_iter()
                    .map(|item| TryInto::<Assignment>::try_into((item.0, item.1))),
            )
            .collect()
    } else {
        let db_assignments: Vec<db_assignment::Model> = select_assignment
            .all(db)
            .await
            .map_err(|err| db_err(err, "fetching role assignments"))?;
        let db_system_assignments: Vec<db_system_assignment::Model> =
            if params.project_id.is_none() && params.domain_id.is_none() {
                // get system scope assignments only when no project or domain is specified
                select_system_assignment
                    .all(db)
                    .await
                    .map_err(|err| db_err(err, "fetching system role assignments"))?
            } else {
                Vec::new()
            };
        db_assignments
            .into_iter()
            .map(TryInto::<Assignment>::try_into)
            .chain(
                db_system_assignments
                    .into_iter()
                    .map(TryInto::<Assignment>::try_into),
            )
            .collect()
    };
    results
}

/// Get all role assignments by list of actors on list of targets.
///
/// It is a naive interpretation of the effective role assignments where we
/// check all roles assigned to the user (including groups) on a concrete target
/// (including all higher targets the role can be inherited from)
pub async fn list_for_multiple_actors_and_targets(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &RoleAssignmentListForMultipleActorTargetParameters,
) -> Result<Vec<Assignment>, AssignmentDatabaseError> {
    let mut select = DbAssignment::find();

    if !params.actors.is_empty() {
        select = select.filter(db_assignment::Column::ActorId.is_in(params.actors.clone()));
    }
    if let Some(rid) = &params.role_id {
        select = select.filter(db_assignment::Column::RoleId.eq(rid));
    }
    if !params.targets.is_empty() {
        let mut cond = Condition::any();
        for target in params.targets.iter() {
            cond = cond.add(
                Condition::all()
                    .add(db_assignment::Column::TargetId.eq(&target.target_id))
                    .add_option(
                        target
                            .inherited
                            .map(|x| db_assignment::Column::Inherited.eq(x)),
                    ),
            );
        }
        select = select.filter(cond);
    }

    // Get all implied rules
    let imply_rules = implied_role::list_rules(db, true).await?;

    let mut db_assignments: BTreeMap<String, db_assignment::Model> = BTreeMap::new();
    // Get assignments resolving the roles inference
    for assignment in select.all(db).await.map_err(|err| {
        db_err(
            err,
            "fetching role assignments for multiple actors and targets",
        )
    })? {
        db_assignments.insert(assignment.role_id.clone(), assignment.clone());
        if let Some(implies) = imply_rules.get(&assignment.role_id) {
            let mut implied_assignment = assignment.clone();
            for implied in implies.iter() {
                implied_assignment.role_id = implied.clone();
                db_assignments.insert(implied.clone(), implied_assignment.clone());
            }
        }
    }

    if !db_assignments.is_empty() {
        // Get roles for the found IDs
        let roles: HashMap<String, String> = HashMap::from_iter(
            DbRole::find()
                .select_only()
                .columns([db_role::Column::Id, db_role::Column::Name])
                .filter(Expr::col(db_role::Column::Id).is_in(db_assignments.keys()))
                .into_tuple()
                .all(db)
                .await
                .map_err(|err| db_err(err, "fetching roles by ids"))?,
        );
        let results: Result<Vec<Assignment>, _> = db_assignments
            .values()
            .map(|item| TryInto::<Assignment>::try_into((item, roles.get(&item.role_id))))
            .collect();
        results
    } else {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::config::Config;
    use crate::db::entity::assignment;

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_list_no_params() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list(&config, &db, &RoleAssignmentListParameters::default())
                .await
                .unwrap(),
            vec![
                Assignment {
                    role_id: "1".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                },
                Assignment {
                    role_id: "1".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: false,
                }
            ]
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "system_assignment"."type", "system_assignment"."actor_id", "system_assignment"."target_id", "system_assignment"."role_id", "system_assignment"."inherited" FROM "system_assignment" WHERE "system_assignment"."target_id" = $1 AND "system_assignment"."inherited" = $2"#,
                    ["system".into(), false.into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_role_id() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list(
                &config,
                &db,
                &RoleAssignmentListParameters {
                    role_id: Some("1".into()),
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
            vec![
                Assignment {
                    role_id: "1".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                },
                Assignment {
                    role_id: "1".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: false,
                }
            ]
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."role_id" = $1"#,
                    ["1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "system_assignment"."type", "system_assignment"."actor_id", "system_assignment"."target_id", "system_assignment"."role_id", "system_assignment"."inherited" FROM "system_assignment" WHERE "system_assignment"."role_id" = $1 AND "system_assignment"."target_id" = $2 AND "system_assignment"."inherited" = $3"#,
                    ["1".into(), "system".into(), false.into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_project_id() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list(
                &config,
                &db,
                &RoleAssignmentListParameters {
                    project_id: Some("target".into()),
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
            vec![Assignment {
                role_id: "1".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: AssignmentType::UserProject,
                inherited: false,
            }]
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."target_id" = $1 AND "assignment"."type" IN (CAST($2 AS "type"), CAST($3 AS "type")) AND "assignment"."inherited" = $4"#,
                [
                    "target".into(),
                    "UserProject".into(),
                    "GroupProject".into(),
                    false.into()
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list_include_names() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_with_role_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_with_role_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list(
                &config,
                &db,
                &RoleAssignmentListParameters {
                    include_names: Some(true),
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
            vec![
                Assignment {
                    role_id: "1".into(),
                    role_name: Some("1".into()),
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                },
                Assignment {
                    role_id: "1".into(),
                    role_name: Some("1".into()),
                    actor_id: "actor".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: false,
                }
            ]
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS "text") AS "A_type", "assignment"."actor_id" AS "A_actor_id", "assignment"."target_id" AS "A_target_id", "assignment"."role_id" AS "A_role_id", "assignment"."inherited" AS "A_inherited", "role"."id" AS "B_id", "role"."name" AS "B_name", "role"."extra" AS "B_extra", "role"."domain_id" AS "B_domain_id", "role"."description" AS "B_description" FROM "assignment" LEFT JOIN "role" ON "assignment"."role_id" = "role"."id""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "system_assignment"."type" AS "A_type", "system_assignment"."actor_id" AS "A_actor_id", "system_assignment"."target_id" AS "A_target_id", "system_assignment"."role_id" AS "A_role_id", "system_assignment"."inherited" AS "A_inherited", "role"."id" AS "B_id", "role"."name" AS "B_name", "role"."extra" AS "B_extra", "role"."domain_id" AS "B_domain_id", "role"."description" AS "B_description" FROM "system_assignment" LEFT JOIN "role" ON "system_assignment"."role_id" = "role"."id" WHERE "system_assignment"."target_id" = $1 AND "system_assignment"."inherited" = $2"#,
                    ["system".into(), false.into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_multiple_actors_single_target() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![
                get_role_mock("1", "rname"),
                get_role_mock("2", "rname2"),
            ]])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec!["uid1".into(), "gid1".into(), "gid2".into()],
                    targets: vec![RoleAssignmentTarget {
                        target_id: "pid1".into(),
                        inherited: None
                    }],
                    role_id: Some("rid".into())
                }
            )
            .await
            .unwrap(),
            vec![
                Assignment {
                    role_id: "1".into(),
                    role_name: Some("rname".into()),
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                },
                Assignment {
                    role_id: "2".into(),
                    role_name: Some("rname2".into()),
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                }
            ]
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."actor_id" IN ($1, $2, $3) AND "assignment"."role_id" = $4 AND "assignment"."target_id" = $5"#,
                    [
                        "uid1".into(),
                        "gid1".into(),
                        "gid2".into(),
                        "rid".into(),
                        "pid1".into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name" FROM "role" WHERE "id" IN ($1, $2)"#,
                    ["1".into(), "2".into(),]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_multiple_complex_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![
                get_role_mock("1", "rname"),
                get_role_mock("2", "rname2"),
            ]])
            .into_connection();
        let config = Config::default();
        // multiple actors multiple complex targets
        assert!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec!["uid1".into(), "gid1".into(), "gid2".into()],
                    targets: vec![
                        RoleAssignmentTarget {
                            target_id: "pid1".into(),
                            inherited: None
                        },
                        RoleAssignmentTarget {
                            target_id: "pid2".into(),
                            inherited: Some(true)
                        }
                    ],
                    role_id: None
                }
            )
            .await
            .is_ok()
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."actor_id" IN ($1, $2, $3) AND ("assignment"."target_id" = $4 OR ("assignment"."target_id" = $5 AND "assignment"."inherited" = $6))"#,
                    [
                        "uid1".into(),
                        "gid1".into(),
                        "gid2".into(),
                        "pid1".into(),
                        "pid2".into(),
                        true.into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name" FROM "role" WHERE "id" IN ($1, $2)"#,
                    ["1".into(), "2".into(),]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_empty_actors_and_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![
                get_role_mock("1", "rname"),
                get_role_mock("2", "rname2"),
            ]])
            .into_connection();
        let config = Config::default();
        //// empty actors and targets
        assert!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec![],
                    targets: vec![],
                    role_id: None
                }
            )
            .await
            .is_ok()
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name" FROM "role" WHERE "id" IN ($1, $2)"#,
                    ["1".into(), "2".into(),]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_mixed_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![
                get_role_mock("1", "rname"),
                get_role_mock("2", "rname2"),
            ]])
            .into_connection();
        let config = Config::default();

        //// only mixed targets
        assert!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec![],
                    targets: vec![
                        RoleAssignmentTarget {
                            target_id: "pid1".into(),
                            inherited: None
                        },
                        RoleAssignmentTarget {
                            target_id: "pid2".into(),
                            inherited: Some(true)
                        }
                    ],
                    role_id: None
                }
            )
            .await
            .is_ok()
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."target_id" = $1 OR ("assignment"."target_id" = $2 AND "assignment"."inherited" = $3)"#,
                    ["pid1".into(), "pid2".into(), true.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name" FROM "role" WHERE "id" IN ($1, $2)"#,
                    ["1".into(), "2".into(),]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_complex_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([get_implied_rules_mock()])
            .append_query_results([Vec::<assignment::Model>::new()])
            .into_connection();
        let config = Config::default();

        //// only complex targets
        assert!(
            list_for_multiple_actors_and_targets(
                &config,
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec![],
                    targets: vec![
                        RoleAssignmentTarget {
                            target_id: "pid1".into(),
                            inherited: Some(false)
                        },
                        RoleAssignmentTarget {
                            target_id: "pid2".into(),
                            inherited: Some(true)
                        }
                    ],
                    role_id: None
                }
            )
            .await
            .is_ok()
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE ("assignment"."target_id" = $1 AND "assignment"."inherited" = $2) OR ("assignment"."target_id" = $3 AND "assignment"."inherited" = $4)"#,
                    ["pid1".into(), false.into(), "pid2".into(), true.into()]
                ),
            ]
        );
    }
}
