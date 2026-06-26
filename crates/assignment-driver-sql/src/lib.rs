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
//! # Assignment driver to the OpenStack Keystone for the SQL database.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::assignment::{AssignmentProviderError, backend::AssignmentBackend};
use openstack_keystone_core::db::create_table;
use openstack_keystone_core::error::DatabaseError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::{SqlDriver, SqlDriverRegistration};
use openstack_keystone_core_types::assignment::*;

use openstack_keystone_core::auth::ExecutionContext;

mod assignment;
pub mod entity;

#[derive(Default)]
pub struct SqlBackend {}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

impl SqlBackend {
    /// Resolve implied roles for a set of assignments.
    ///
    /// Fetches role imply rules, computes transitive closure, and generates
    /// assignment entries for each implied role. Does NOT resolve role names
    /// (that's the provider's responsibility).
    ///
    /// Returns a `Vec<Assignment>` containing both the original assignments
    /// and any additionally generated implied role assignments.
    #[tracing::instrument(level = "info", skip(self, state, assignments))]
    async fn resolve_implied_roles(
        &self,
        state: &ServiceState,
        assignments: Vec<Assignment>,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let exec = ExecutionContext::internal(state);
        let rules = state
            .provider
            .get_role_provider()
            .list_role_imply_rules(&exec)
            .await?;
        let mut imply_rules: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for rule in &rules {
            imply_rules
                .entry(rule.prior_role.id.clone())
                .or_default()
                .insert(rule.implied_role.id.clone());
        }
        // Transitive expansion
        let mut changed = true;
        while changed {
            changed = false;
            let snapshot: Vec<(String, BTreeSet<String>)> = imply_rules
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (snapshot_role_id, snapshot_implied) in snapshot {
                let to_add: BTreeSet<String> = snapshot_implied
                    .iter()
                    .filter_map(|implied_id| {
                        imply_rules.get(implied_id).map(|further| {
                            further
                                .iter()
                                .filter(|fid| {
                                    !imply_rules.get(&snapshot_role_id).unwrap().contains(*fid)
                                })
                                .cloned()
                                .collect::<BTreeSet<String>>()
                        })
                    })
                    .flatten()
                    .collect();
                if !to_add.is_empty() {
                    changed = true;
                    for fid in to_add {
                        imply_rules
                            .entry(snapshot_role_id.clone())
                            .or_default()
                            .insert(fid);
                    }
                }
            }
        }

        // Merge and apply role implies
        let mut result_map: HashSet<Assignment> = HashSet::new();

        for assignment in assignments {
            result_map.insert(assignment.clone());

            if let Some(implies) = imply_rules.get(&assignment.role_id) {
                for implied_role_id in implies {
                    let mut implied_assignment = assignment.clone();
                    implied_assignment.role_id = implied_role_id.clone();
                    implied_assignment.implied_via = Some(assignment.role_id.clone());
                    result_map.insert(implied_assignment);
                }
            }
        }

        Ok(result_map.into_iter().collect())
    }

    /// List role assignments for multiple actors/targets.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `params` - The list parameters.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec` of `Assignment` if successful, or an
    /// `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_assignments_for_multiple_actors_and_targets(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListForMultipleActorTargetParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let assignments =
            assignment::list_for_multiple_actors_and_targets(&state.db, params).await?;

        if params.resolve_implied_roles {
            self.resolve_implied_roles(state, assignments).await
        } else {
            Ok(assignments)
        }
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Set up the database tables.
    ///
    /// # Parameters
    ///
    /// * `connection` - The database connection.
    /// * `schema` - The database schema.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or a `DatabaseError`.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::Assignment).await?;
        create_table(connection, schema, crate::entity::prelude::SystemAssignment).await?;
        Ok(())
    }
}

#[async_trait]
impl AssignmentBackend for SqlBackend {
    /// Check assignment grant.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `grant` - The assignment to check.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `bool` indicating if the grant exists, or an
    /// `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn check_grant(
        &self,
        state: &ServiceState,
        grant: &Assignment,
    ) -> Result<bool, AssignmentProviderError> {
        Ok(assignment::check(&state.db, grant).await?)
    }

    /// Create assignment grant.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `grant` - The assignment to create.
    ///
    /// # Returns
    ///
    /// A `Result` containing the created `Assignment` if successful, or an
    /// `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_grant(
        &self,
        state: &ServiceState,
        grant: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        Ok(assignment::create(&state.db, grant).await?)
    }

    /// List role assignments.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `params` - The list parameters.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec` of `Assignment` if successful, or an
    /// `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let mut request = RoleAssignmentListForMultipleActorTargetParametersBuilder::default();
        let mut actors: Vec<String> = Vec::new();
        let mut targets: Vec<RoleAssignmentTarget> = Vec::new();
        if let Some(role_id) = &params.role_id {
            request.role_id(role_id);
        }
        if let Some(uid) = &params.user_id {
            actors.push(uid.into());
        }
        if let Some(true) = &params.effective
            && let Some(uid) = &params.user_id
        {
            // Effective assignments mean we need to expand user_id to list of all groups
            // the user is member of.
            let users = state
                .provider
                .get_identity_provider()
                .list_groups_of_user(&ExecutionContext::internal(state), uid)
                .await?;
            actors.extend(users.into_iter().map(|x| x.id));
        };
        if let Some(val) = &params.project_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::Project,
                inherited: Some(false),
            });
            if let Some(parents) = state
                .provider
                .get_resource_provider()
                .get_project_parents(&ExecutionContext::internal(state), val)
                .await?
            {
                // All assignments for parent projects having `inherited=true` must be included.
                parents.iter().for_each(|parent_project| {
                    targets.push(RoleAssignmentTarget {
                        id: parent_project.id.clone(),
                        r#type: RoleAssignmentTargetType::Project,
                        inherited: Some(true),
                    });
                });
            }
        } else if let Some(val) = &params.domain_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::Domain,
                inherited: Some(false),
            });
        } else if let Some(val) = &params.system_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::System,
                inherited: Some(false),
            })
        }
        request.targets(targets);
        request.actors(actors);
        request.resolve_implied_roles(params.resolve_implied_roles);
        self.list_assignments_for_multiple_actors_and_targets(state, &request.build()?)
            .await
    }

    /// Revoke assignment grant.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `grant` - The assignment to revoke.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an `Error`.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        grant: &Assignment,
    ) -> Result<(), AssignmentProviderError> {
        Ok(assignment::delete(&state.db, grant).await?)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, DatabaseConnection, MockDatabase};
    use std::sync::Arc;

    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core::provider::Provider;
    use openstack_keystone_core::role::MockRoleProvider;
    use openstack_keystone_core_types::role::{RoleImplyBuilder, RoleRef};

    use super::assignment::tests::*;
    use super::*;

    async fn get_mock_state(db: DatabaseConnection, provider: Provider) -> Arc<Service> {
        Arc::new(
            Service::new(
                ConfigManager::not_watched(Config::default()),
                db,
                provider,
                Arc::new(MockPolicy::default()),
                None,
            )
            .await
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_multiple_actors() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("3")]])
            .into_connection();

        let mut role_mock = MockRoleProvider::default();
        role_mock.expect_list_role_imply_rules().returning(|_e| {
            Ok(vec![
                RoleImplyBuilder::default()
                    .prior_role(RoleRef {
                        id: "1".into(),
                        name: Some("r1".into()),
                        domain_id: None,
                    })
                    .implied_role(RoleRef {
                        id: "2".into(),
                        name: Some("r2".into()),
                        domain_id: None,
                    })
                    .build()
                    .unwrap(),
            ])
        });
        let provider = Provider::mocked_builder()
            .mock_role(role_mock)
            .build()
            .unwrap();

        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend {};
        let res = sot
            .list_assignments_for_multiple_actors_and_targets(
                &state,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    resolve_implied_roles: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(3, res.len(), "{:?}", res);
        assert!(res.contains(&Assignment {
            role_id: "1".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }));
        assert!(res.contains(&Assignment {
            role_id: "2".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: Some("1".into()),
        }));
        assert!(res.contains(&Assignment {
            role_id: "3".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "system".into(),
            r#type: AssignmentType::UserSystem,
            inherited: false,
            implied_via: None,
        }));
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_no_implied_roles() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("3")]])
            .into_connection();

        let provider = Provider::mocked_builder().build().unwrap();

        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend {};
        let res = sot
            .list_assignments_for_multiple_actors_and_targets(
                &state,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    resolve_implied_roles: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(2, res.len(), "{:?}", res);
        assert!(res.contains(&Assignment {
            role_id: "1".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }));
        assert!(res.contains(&Assignment {
            role_id: "3".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "system".into(),
            r#type: AssignmentType::UserSystem,
            inherited: false,
            implied_via: None,
        }));
        // No implied role (role_id "2") should be present
        assert!(
            res.iter().all(|a| a.role_id != "2"),
            "implied role should not be present"
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_no_target_role_id_collision() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("1")]])
            .into_connection();

        let mut role_mock = MockRoleProvider::default();
        role_mock.expect_list_role_imply_rules().returning(|_e| {
            Ok(vec![
                RoleImplyBuilder::default()
                    .prior_role(RoleRef {
                        id: "1".into(),
                        name: Some("r1".into()),
                        domain_id: None,
                    })
                    .implied_role(RoleRef {
                        id: "2".into(),
                        name: Some("r2".into()),
                        domain_id: None,
                    })
                    .build()
                    .unwrap(),
            ])
        });
        let provider = Provider::mocked_builder()
            .mock_role(role_mock)
            .build()
            .unwrap();

        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend {};
        let params = RoleAssignmentListForMultipleActorTargetParameters {
            actors: vec!["uid1".into()],
            resolve_implied_roles: true,
            ..Default::default()
        };
        let res = sot
            .list_assignments_for_multiple_actors_and_targets(&state, &params)
            .await
            .unwrap();

        assert_eq!(4, res.len());

        assert!(
            res.contains(&Assignment {
                role_id: "1".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: AssignmentType::UserProject,
                inherited: false,
                implied_via: None,
            }),
            "in {:?}",
            res
        );
        assert!(
            res.contains(&Assignment {
                role_id: "2".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: AssignmentType::UserProject,
                inherited: false,
                implied_via: Some("1".into()),
            }),
            "in {:?}",
            res
        );
        assert!(
            res.contains(&Assignment {
                role_id: "1".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "system".into(),
                r#type: AssignmentType::UserSystem,
                inherited: false,
                implied_via: None,
            }),
            "in {:?}",
            res
        );
        assert!(
            res.contains(&Assignment {
                role_id: "2".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "system".into(),
                r#type: AssignmentType::UserSystem,
                inherited: false,
                implied_via: Some("1".into()),
            }),
            "in {:?}",
            res
        );
    }
}
