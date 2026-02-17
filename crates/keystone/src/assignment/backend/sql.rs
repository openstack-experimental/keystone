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

use async_trait::async_trait;
use std::collections::{BTreeMap, HashSet};

use super::super::types::*;
use crate::assignment::{AssignmentProviderError, backend::AssignmentBackend};
use crate::keystone::ServiceState;
use crate::role::{
    RoleApi,
    types::{Role, RoleListParameters},
};

pub(crate) mod assignment;

#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl AssignmentBackend for SqlBackend {
    /// Check assignment grant.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn check_grant(
        &self,
        state: &ServiceState,
        grant: &Assignment,
    ) -> Result<bool, AssignmentProviderError> {
        Ok(assignment::check(&state.db, grant).await?)
    }

    /// Create assignment grant.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_grant(
        &self,
        state: &ServiceState,
        grant: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        Ok(assignment::create(&state.db, grant).await?)
    }

    /// List role assignments.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let mut assignments = assignment::list(&state.db, params).await?;
        if params.include_names.is_some_and(|x| x) {
            let roles: BTreeMap<String, Role> = state
                .provider
                .get_role_provider()
                .list_roles(state, &RoleListParameters::default())
                .await?
                .into_iter()
                .map(|x| (x.id.clone(), x))
                .collect();
            for assignment in assignments.iter_mut() {
                assignment.role_name = roles.get(&assignment.role_id).map(|role| role.name.clone());
            }
        }
        Ok(assignments)
    }

    /// List role assignments for multiple actors/targets.
    ///
    /// List all role assignments matching the parameters resolving the imply
    /// rules and role names.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_assignments_for_multiple_actors_and_targets(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListForMultipleActorTargetParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let role_list_qp = RoleListParameters::default();
        let (assignments_handle, imply_rules_handle, role_handle) = tokio::join!(
            assignment::list_for_multiple_actors_and_targets(&state.db, params),
            state
                .provider
                .get_role_provider()
                .list_imply_rules(state, true),
            state
                .provider
                .get_role_provider()
                .list_roles(state, &role_list_qp)
        );
        let imply_rules = imply_rules_handle?;
        let roles: BTreeMap<String, Role> = role_handle?
            .into_iter()
            .map(|x| (x.id.clone(), x))
            .collect();

        // Merge and apply role implies
        let mut result_map: HashSet<Assignment> = HashSet::new();

        for assignment in assignments_handle?.iter_mut() {
            assignment.role_name = roles.get(&assignment.role_id).map(|role| role.name.clone());
            result_map.insert(assignment.clone());

            if let Some(implies) = imply_rules.get(&assignment.role_id) {
                for implied_role_id in implies.iter() {
                    let mut implied_assignment = assignment.clone();
                    implied_assignment.role_id = implied_role_id.clone();
                    implied_assignment.role_name =
                        roles.get(implied_role_id).map(|role| role.name.clone());
                    implied_assignment.implied_via = Some(assignment.role_id.clone());
                    result_map.insert(implied_assignment);
                }
            }
        }

        Ok(result_map.into_iter().collect())
    }

    /// Revoke assignment grant.
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
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use super::assignment::tests::*;
    use super::*;
    use crate::config::Config;
    use crate::keystone::Service;
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;
    use crate::role::{MockRoleProvider, types::Role};

    #[tokio::test]
    async fn test_list_include_names() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("1")]])
            .into_connection();

        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, _: &RoleListParameters| true)
            .returning(|_, _| {
                Ok(vec![Role {
                    id: "1".into(),
                    name: "r1".into(),
                    ..Default::default()
                }])
            });
        let provider = Provider::mocked_builder().role(role_mock).build().unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                db,
                provider,
                MockPolicyFactory::default(),
            )
            .unwrap(),
        );

        let sot = SqlBackend {};
        let res = sot
            .list_assignments(
                &state,
                &RoleAssignmentListParameters {
                    include_names: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(
            res,
            vec![
                Assignment {
                    role_id: "1".into(),
                    role_name: Some("r1".into()),
                    actor_id: "actor".into(),
                    target_id: "target".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                },
                Assignment {
                    role_id: "1".into(),
                    role_name: Some("r1".into()),
                    actor_id: "actor".into(),
                    target_id: "system".into(),
                    r#type: AssignmentType::UserSystem,
                    inherited: false,
                    implied_via: None,
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_multiple_actors() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("3")]])
            .into_connection();

        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_imply_rules()
            .withf(|_, resolve: &bool| *resolve)
            .returning(|_, _| Ok(BTreeMap::from([("1".into(), BTreeSet::from(["2".into()]))])));
        role_mock
            .expect_list_roles()
            .withf(|_, _: &RoleListParameters| true)
            .returning(|_, _| {
                Ok(vec![
                    Role {
                        id: "1".into(),
                        name: "r1".into(),
                        ..Default::default()
                    },
                    Role {
                        id: "2".into(),
                        name: "r2".into(),
                        ..Default::default()
                    },
                    Role {
                        id: "3".into(),
                        name: "r3".into(),
                        ..Default::default()
                    },
                ])
            });
        let provider = Provider::mocked_builder().role(role_mock).build().unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                db,
                provider,
                MockPolicyFactory::default(),
            )
            .unwrap(),
        );

        let sot = SqlBackend {};
        let res = sot
            .list_assignments_for_multiple_actors_and_targets(
                &state,
                &RoleAssignmentListForMultipleActorTargetParameters::default(),
            )
            .await
            .unwrap();

        assert_eq!(3, res.len(), "{:?}", res);
        assert!(res.contains(&Assignment {
            role_id: "1".into(),
            role_name: Some("r1".into()),
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }));
        assert!(res.contains(&Assignment {
            role_id: "2".into(),
            role_name: Some("r2".into()),
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: Some("1".into()),
        }));
        assert!(res.contains(&Assignment {
            role_id: "3".into(),
            role_name: Some("r3".into()),
            actor_id: "actor".into(),
            target_id: "system".into(),
            r#type: AssignmentType::UserSystem,
            inherited: false,
            implied_via: None,
        }));
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_no_target_role_id_collision() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("1")]])
            .into_connection();

        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_imply_rules()
            .withf(|_, resolve: &bool| *resolve)
            .returning(|_, _| Ok(BTreeMap::from([("1".into(), BTreeSet::from(["2".into()]))])));
        role_mock
            .expect_list_roles()
            .withf(|_, _: &RoleListParameters| true)
            .returning(|_, _| {
                Ok(vec![
                    Role {
                        id: "1".into(),
                        name: "r1".into(),
                        ..Default::default()
                    },
                    Role {
                        id: "2".into(),
                        name: "r2".into(),
                        ..Default::default()
                    },
                ])
            });
        let provider = Provider::mocked_builder().role(role_mock).build().unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                db,
                provider,
                MockPolicyFactory::default(),
            )
            .unwrap(),
        );

        let sot = SqlBackend {};
        let params = RoleAssignmentListForMultipleActorTargetParameters {
            actors: vec!["uid1".into()],
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
                role_name: Some("r1".into()),
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
                role_name: Some("r2".into()),
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
                role_name: Some("r1".into()),
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
                role_name: Some("r2".into()),
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
