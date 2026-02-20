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

use crate::assignment::{
    AssignmentProviderError,
    types::{
        Assignment, RoleAssignmentListForMultipleActorTargetParameters,
        RoleAssignmentListParameters, RoleAssignmentTargetType,
    },
};
use crate::db::entity::{
    assignment as db_assignment,
    prelude::{Assignment as DbAssignment, SystemAssignment as DbSystemAssignment},
    sea_orm_active_enums::Type as DbAssignmentType,
    system_assignment as db_system_assignment,
};
use crate::error::DbContextExt;

/// List direct role assignments.
pub async fn list(
    db: &DatabaseConnection,
    params: &RoleAssignmentListParameters,
) -> Result<Vec<Assignment>, AssignmentProviderError> {
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

    let db_assignments: Vec<db_assignment::Model> = select_assignment
        .all(db)
        .await
        .context("fetching role assignments")?;
    let db_system_assignments: Vec<db_system_assignment::Model> =
        if params.project_id.is_none() && params.domain_id.is_none() {
            // get system scope assignments only when no project or domain is specified
            select_system_assignment
                .all(db)
                .await
                .context("fetching system role assignments")?
        } else {
            Vec::new()
        };
    db_assignments
        .into_iter()
        .map(|val| Ok(Into::<Assignment>::into(val)))
        .chain(
            db_system_assignments
                .into_iter()
                .map(TryInto::<Assignment>::try_into),
        )
        .collect()
}

/// Get all role assignments by list of actors on list of targets.
///
/// It is a naive interpretation of the effective role assignments where we
/// check all roles assigned to the user (including groups) on a concrete target
/// (including all higher targets the role can be inherited from).
///
/// This method does not resolve the implied roles and the resulting list will
/// not have `role_name` set.
pub async fn list_for_multiple_actors_and_targets(
    db: &DatabaseConnection,
    params: &RoleAssignmentListForMultipleActorTargetParameters,
) -> Result<Vec<Assignment>, AssignmentProviderError> {
    // Query both assignment tables in parallel and imply rules
    //let db = &state.db;
    let db_res = tokio::try_join!(
        // Result assignments
        list_for_multiple_actors_and_targets_regular(db, params),
        // System assignments
        list_for_multiple_actors_and_targets_system(db, params),
    )?;

    Ok([db_res.0, db_res.1]
        .into_iter()
        // discard None
        .flatten()
        // convert iter of items to items themselves
        .flatten()
        .collect())
}

/// Select regular assignments.
///
/// Return Vec<Assignment> for the regular role assignments or `None` when no
/// corresponding targets were given in the query parameters.
async fn list_for_multiple_actors_and_targets_regular(
    db: &DatabaseConnection,
    params: &RoleAssignmentListForMultipleActorTargetParameters,
) -> Result<Option<Vec<Assignment>>, AssignmentProviderError> {
    let mut select = DbAssignment::find();
    let mut should_return = false;

    if !params.actors.is_empty() {
        select = select.filter(db_assignment::Column::ActorId.is_in(params.actors.clone()));
    }
    if let Some(rid) = &params.role_id {
        select = select.filter(db_assignment::Column::RoleId.eq(rid));
    }
    if !params.targets.is_empty() {
        let mut cond = Condition::any();
        for target in params.targets.iter() {
            match target.r#type {
                RoleAssignmentTargetType::Domain | RoleAssignmentTargetType::Project => {
                    cond = cond.add(
                        Condition::all()
                            .add(db_assignment::Column::TargetId.eq(&target.id))
                            .add_option(
                                target
                                    .inherited
                                    .map(|x| db_assignment::Column::Inherited.eq(x)),
                            ),
                    );
                    should_return = true;
                }
                _ => {}
            };
        }
        select = select.filter(cond);
    } else {
        // When no targets requested we still query assignments.
        should_return = true;
    }

    if should_return {
        Ok(Some(
            select
                .all(db)
                .await
                .context("fetching role assignments")?
                .into_iter()
                .map(Into::into)
                .collect(),
        ))
    } else {
        Ok(None)
    }
}

/// Select system assignments.
///
/// Return Vec<Assignment> for the regular role assignments or `None` when no
/// corresponding targets were given in the query parameters.
async fn list_for_multiple_actors_and_targets_system(
    db: &DatabaseConnection,
    params: &RoleAssignmentListForMultipleActorTargetParameters,
) -> Result<Option<Vec<Assignment>>, AssignmentProviderError> {
    let mut select_system = DbSystemAssignment::find();
    let mut should_return = false;

    if !params.actors.is_empty() {
        select_system = select_system
            .filter(db_system_assignment::Column::ActorId.is_in(params.actors.clone()));
    }
    if let Some(rid) = &params.role_id {
        select_system = select_system.filter(db_system_assignment::Column::RoleId.eq(rid));
    }
    if !params.targets.is_empty() {
        let mut system_cond = Condition::any();
        for target in params.targets.iter() {
            if let RoleAssignmentTargetType::System = target.r#type {
                system_cond = system_cond.add(
                    Condition::all()
                        .add(db_system_assignment::Column::TargetId.eq(&target.id))
                        .add_option(
                            target
                                .inherited
                                .map(|x| db_system_assignment::Column::Inherited.eq(x)),
                        ),
                );
                should_return = true;
            };
        }
        select_system = select_system.filter(system_cond);
    } else {
        // When no targets requested we still query assignments.
        should_return = true;
    }

    if should_return {
        Ok(Some(
            select_system
                .all(db)
                .await
                .context("fetching system role assignments")?
                .into_iter()
                .map(TryInto::<Assignment>::try_into)
                .collect::<Result<Vec<_>, _>>()?,
        ))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::db::entity::assignment;

    use super::super::tests::*;
    use super::*;
    use crate::assignment::types::{AssignmentType, RoleAssignmentTarget};

    #[tokio::test]
    async fn test_list_no_params() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("1")]])
            .into_connection();
        assert_eq!(
            list(&db, &RoleAssignmentListParameters::default())
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
                    implied_via: None,
                },
                Assignment {
                    role_id: "1".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: false,
                    implied_via: None,
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
        assert_eq!(
            list(
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
                    implied_via: None,
                },
                Assignment {
                    role_id: "1".into(),
                    role_name: None,
                    actor_id: "actor".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: false,
                    implied_via: None,
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
        assert_eq!(
            list(
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
                implied_via: None,
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
    async fn test_list_for_multiple_actor_targets_multiple_actors_single_target() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("1")]])
            .into_connection();
        let res = list_for_multiple_actors_and_targets(
            &db,
            &RoleAssignmentListForMultipleActorTargetParameters {
                actors: vec!["uid1".into(), "gid1".into(), "gid2".into()],
                targets: vec![RoleAssignmentTarget {
                    id: "pid1".into(),
                    r#type: RoleAssignmentTargetType::Project,
                    inherited: None,
                }],
                role_id: Some("rid".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(1, res.len());
        assert!(res.contains(&Assignment {
            role_id: "1".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }));
        // system target
        let res = list_for_multiple_actors_and_targets(
            &db,
            &RoleAssignmentListForMultipleActorTargetParameters {
                actors: vec!["uid1".into(), "gid1".into(), "gid2".into()],
                targets: vec![RoleAssignmentTarget {
                    id: "system".into(),
                    r#type: RoleAssignmentTargetType::System,
                    inherited: None,
                }],
                role_id: Some("rid".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(1, res.len());
        assert!(res.contains(&Assignment {
            role_id: "1".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "system".into(),
            r#type: AssignmentType::UserSystem,
            inherited: false,
            implied_via: None,
        }));
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
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
                    r#"SELECT "system_assignment"."type", "system_assignment"."actor_id", "system_assignment"."target_id", "system_assignment"."role_id", "system_assignment"."inherited" FROM "system_assignment" WHERE "system_assignment"."actor_id" IN ($1, $2, $3) AND "system_assignment"."role_id" = $4 AND "system_assignment"."target_id" = $5"#,
                    [
                        "uid1".into(),
                        "gid1".into(),
                        "gid2".into(),
                        "rid".into(),
                        "system".into()
                    ]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_multiple_complex_targets() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .into_connection();
        // multiple actors multiple complex targets
        list_for_multiple_actors_and_targets(
            &db,
            &RoleAssignmentListForMultipleActorTargetParameters {
                actors: vec!["uid1".into(), "gid1".into(), "gid2".into()],
                targets: vec![
                    RoleAssignmentTarget {
                        id: "pid1".into(),
                        r#type: RoleAssignmentTargetType::Project,
                        inherited: None,
                    },
                    RoleAssignmentTarget {
                        id: "pid2".into(),
                        r#type: RoleAssignmentTargetType::Project,
                        inherited: Some(true),
                    },
                ],
                role_id: None,
            },
        )
        .await
        .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
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
            ),]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_empty_actors_and_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("2")]])
            .into_connection();
        //// empty actors and targets
        //assert!(
        list_for_multiple_actors_and_targets(
            &db,
            &RoleAssignmentListForMultipleActorTargetParameters {
                actors: vec![],
                targets: vec![],
                role_id: None,
            },
        )
        .await
        .unwrap();
        //    .is_ok()
        //);

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
                    r#"SELECT "system_assignment"."type", "system_assignment"."actor_id", "system_assignment"."target_id", "system_assignment"."role_id", "system_assignment"."inherited" FROM "system_assignment""#,
                    []
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_mixed_targets() {
        // Create MockDatabase with mock query results

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .into_connection();

        //// only mixed targets
        assert!(
            list_for_multiple_actors_and_targets(
                &db,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    actors: vec![],
                    targets: vec![
                        RoleAssignmentTarget {
                            id: "pid1".into(),
                            r#type: RoleAssignmentTargetType::Project,
                            inherited: None
                        },
                        RoleAssignmentTarget {
                            id: "pid2".into(),
                            r#type: RoleAssignmentTargetType::Project,
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
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE "assignment"."target_id" = $1 OR ("assignment"."target_id" = $2 AND "assignment"."inherited" = $3)"#,
                ["pid1".into(), "pid2".into(), true.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_complex_targets() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<assignment::Model>::new()])
            .into_connection();

        //// only complex targets
        list_for_multiple_actors_and_targets(
            &db,
            &RoleAssignmentListForMultipleActorTargetParameters {
                actors: vec![],
                targets: vec![
                    RoleAssignmentTarget {
                        id: "pid1".into(),
                        r#type: RoleAssignmentTargetType::Project,
                        inherited: Some(false),
                    },
                    RoleAssignmentTarget {
                        id: "pid2".into(),
                        r#type: RoleAssignmentTargetType::Project,
                        inherited: Some(true),
                    },
                ],
                role_id: None,
            },
        )
        .await
        .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT CAST("assignment"."type" AS "text"), "assignment"."actor_id", "assignment"."target_id", "assignment"."role_id", "assignment"."inherited" FROM "assignment" WHERE ("assignment"."target_id" = $1 AND "assignment"."inherited" = $2) OR ("assignment"."target_id" = $3 AND "assignment"."inherited" = $4)"#,
                ["pid1".into(), false.into(), "pid2".into(), true.into()]
            ),]
        );
    }
}
