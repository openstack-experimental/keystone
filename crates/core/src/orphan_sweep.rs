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
//! Orphan sweep: reports role assignments whose actor or target no longer
//! exists.
//!
//! The delete cascades (user, project, domain) remove the dependent
//! assignments in the owning service, but they cannot reach every case: the
//! inheritable grants on a deleted domain, the grants a deleted group holds
//! on targets of other domains, and anything removed by a writer that emits
//! no event (a co-deployed Python Keystone, a crashed node mid-cascade). This
//! sweep is the safety net for those leftovers.
//!
//! It is report-only: an assignment that points nowhere grants nothing that
//! the owning services can still resolve, so the sweep logs what it found and
//! leaves removal to an operator until the false-positive rate on real
//! deployments is known. Orphans are identified by IDs only.
//!
//! The pass is read-only and idempotent, so it runs on every node, merely
//! redundantly on a cluster.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use tracing::{info, warn};

use openstack_keystone_core_types::assignment::{
    Assignment, AssignmentType, RoleAssignmentListParameters,
};

use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;

/// Seconds between two sweeps.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Orphans listed in the log per pass; the report carries the full count.
const MAX_LOGGED: usize = 20;

/// What of an assignment no longer exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Missing {
    /// The user or group holding the role.
    Actor,
    /// The project or domain the role is granted on.
    Target,
    /// Both of them.
    Both,
}

/// An assignment pointing at a missing actor and/or target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanedAssignment {
    /// The assignment.
    pub assignment: Assignment,
    /// What is missing.
    pub missing: Missing,
}

/// Outcome of a single sweep pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OrphanReport {
    /// Assignments examined.
    pub checked: usize,
    /// Assignments pointing at something that no longer exists.
    pub orphans: Vec<OrphanedAssignment>,
    /// Existence lookups that failed. A failed lookup is never reported as an
    /// orphan: the entity may well exist.
    pub errors: usize,
    /// The failed lookups per kind of entity, e.g. a read-only identity
    /// backend that cannot be reached shows up as failing users.
    pub errors_by_kind: BTreeMap<Kind, usize>,
}

/// Kind of the entity an existence lookup is about.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Kind {
    /// A user.
    User,
    /// A group.
    Group,
    /// A domain.
    Domain,
    /// A project.
    Project,
}

/// Existence lookups of one pass, cached by `(kind, id)`.
struct Lookup<'a, 'b> {
    ctx: &'a ExecutionContext<'b>,
    state: &'a ServiceState,
    cache: HashMap<(Kind, String), Option<bool>>,
    errors: BTreeMap<Kind, usize>,
}

impl Lookup<'_, '_> {
    /// `Some(exists)`, or `None` when the lookup failed.
    async fn exists(&mut self, kind: Kind, id: &str) -> Option<bool> {
        if let Some(known) = self.cache.get(&(kind, id.to_string())) {
            return *known;
        }
        let provider = &self.state.provider;
        let res = match kind {
            Kind::User => provider
                .get_identity_provider()
                .get_user(self.ctx, id)
                .await
                .map(|x| x.is_some())
                .map_err(|e| e.to_string()),
            Kind::Group => provider
                .get_identity_provider()
                .get_group(self.ctx, id)
                .await
                .map(|x| x.is_some())
                .map_err(|e| e.to_string()),
            Kind::Domain => provider
                .get_resource_provider()
                .get_domain(self.ctx, id)
                .await
                .map(|x| x.is_some())
                .map_err(|e| e.to_string()),
            Kind::Project => provider
                .get_resource_provider()
                .get_project(self.ctx, id)
                .await
                .map(|x| x.is_some())
                .map_err(|e| e.to_string()),
        };
        let known = match res {
            Ok(exists) => Some(exists),
            Err(error) => {
                warn!(?kind, id, %error, "orphan sweep: existence lookup failed");
                *self.errors.entry(kind).or_default() += 1;
                None
            }
        };
        self.cache.insert((kind, id.to_string()), known);
        known
    }
}

/// The kind of actor and, unless it is the system, of target.
fn kinds(assignment: &Assignment) -> (Kind, Option<Kind>) {
    match assignment.r#type {
        AssignmentType::UserDomain => (Kind::User, Some(Kind::Domain)),
        AssignmentType::UserProject => (Kind::User, Some(Kind::Project)),
        AssignmentType::UserSystem => (Kind::User, None),
        AssignmentType::GroupDomain => (Kind::Group, Some(Kind::Domain)),
        AssignmentType::GroupProject => (Kind::Group, Some(Kind::Project)),
        AssignmentType::GroupSystem => (Kind::Group, None),
    }
}

/// Run a single sweep pass over every assignment.
pub async fn run_once(
    state: &ServiceState,
) -> Result<OrphanReport, crate::assignment::AssignmentProviderError> {
    let ctx = ExecutionContext::internal(state);
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(&ctx, &RoleAssignmentListParameters::default())
        .await?;

    let mut lookup = Lookup {
        ctx: &ctx,
        state,
        cache: HashMap::new(),
        errors: BTreeMap::new(),
    };
    let mut report = OrphanReport {
        checked: assignments.len(),
        ..Default::default()
    };
    for assignment in assignments {
        let (actor_kind, target_kind) = kinds(&assignment);
        let actor_gone = lookup.exists(actor_kind, &assignment.actor_id).await == Some(false);
        let target_gone = match target_kind {
            Some(kind) => lookup.exists(kind, &assignment.target_id).await == Some(false),
            None => false,
        };
        let missing = match (actor_gone, target_gone) {
            (true, true) => Missing::Both,
            (true, false) => Missing::Actor,
            (false, true) => Missing::Target,
            (false, false) => continue,
        };
        report.orphans.push(OrphanedAssignment {
            assignment,
            missing,
        });
    }
    report.errors = lookup.errors.values().sum();
    report.errors_by_kind = lookup.errors;
    Ok(report)
}

/// Spawn the background sweep loop. Intended to be called once at server
/// startup with the long-lived `ServiceState`.
pub fn spawn(state: ServiceState) {
    tokio::spawn(async move {
        // The first sweep runs one interval after startup, not during boot.
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            match run_once(&state).await {
                Ok(report) if !report.orphans.is_empty() => {
                    warn!(
                        checked = report.checked,
                        orphans = report.orphans.len(),
                        errors = report.errors,
                        errors_by_kind = ?report.errors_by_kind,
                        "orphan sweep: role assignments point at deleted users, groups, projects or domains"
                    );
                    for orphan in report.orphans.iter().take(MAX_LOGGED) {
                        warn!(
                            actor_id = %orphan.assignment.actor_id,
                            target_id = %orphan.assignment.target_id,
                            role_id = %orphan.assignment.role_id,
                            assignment_type = ?orphan.assignment.r#type,
                            missing = ?orphan.missing,
                            "orphaned role assignment"
                        );
                    }
                }
                Ok(report) => info!(
                    checked = report.checked,
                    errors = report.errors,
                    errors_by_kind = ?report.errors_by_kind,
                    "orphan sweep: no orphaned role assignments"
                ),
                Err(error) => warn!(%error, "orphan sweep: listing assignments failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    use openstack_keystone_core_types::assignment::AssignmentBuilder;
    use openstack_keystone_core_types::identity::{GroupBuilder, UserResponseBuilder};
    use openstack_keystone_core_types::resource::{DomainBuilder, ProjectBuilder};

    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::tests::get_mocked_state;

    fn assignment(actor: &str, target: &str, r#type: AssignmentType) -> Assignment {
        AssignmentBuilder::default()
            .actor_id(actor)
            .role_id("rid")
            .target_id(target)
            .r#type(r#type)
            .build()
            .unwrap()
    }

    /// Users `u-live`, groups `g-live`, project `p-live`, domain `d-live`
    /// exist; everything else is gone.
    async fn state_with(assignments: Vec<Assignment>) -> ServiceState {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(move |_, _| Ok(assignments.clone()));
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(|_, id: &'_ str| {
            Ok((id == "u-live").then(|| {
                UserResponseBuilder::default()
                    .id(id)
                    .domain_id("d-live")
                    .enabled(true)
                    .name(id)
                    .build()
                    .unwrap()
            }))
        });
        identity.expect_get_group().returning(|_, id: &'_ str| {
            Ok((id == "g-live").then(|| {
                GroupBuilder::default()
                    .id(id)
                    .domain_id("d-live")
                    .name(id)
                    .build()
                    .unwrap()
            }))
        });
        let mut resource = MockResourceProvider::default();
        resource.expect_get_domain().returning(|_, id: &'_ str| {
            Ok((id == "d-live").then(|| {
                DomainBuilder::default()
                    .id(id)
                    .name(id)
                    .enabled(true)
                    .build()
                    .unwrap()
            }))
        });
        resource.expect_get_project().returning(|_, id: &'_ str| {
            Ok((id == "p-live").then(|| {
                ProjectBuilder::default()
                    .id(id)
                    .domain_id("d-live")
                    .name(id)
                    .enabled(true)
                    .build()
                    .unwrap()
            }))
        });
        get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock)
                    .mock_identity(identity)
                    .mock_resource(resource),
            ),
        )
        .await
    }

    #[tokio::test]
    async fn test_reports_missing_actor_target_and_both() {
        let state = state_with(vec![
            assignment("u-live", "p-live", AssignmentType::UserProject),
            assignment("u-gone", "p-live", AssignmentType::UserProject),
            assignment("g-live", "d-gone", AssignmentType::GroupDomain),
            assignment("g-gone", "p-gone", AssignmentType::GroupProject),
        ])
        .await;

        let report = run_once(&state).await.unwrap();

        assert_eq!(report.checked, 4);
        assert_eq!(report.errors, 0);
        let found: Vec<(&str, Missing)> = report
            .orphans
            .iter()
            .map(|x| (x.assignment.actor_id.as_str(), x.missing))
            .collect();
        assert_eq!(
            found,
            [
                ("u-gone", Missing::Actor),
                ("g-live", Missing::Target),
                ("g-gone", Missing::Both),
            ]
        );
    }

    #[tokio::test]
    async fn test_system_assignment_target_is_not_looked_up() {
        // The target of a system grant is not a project or domain; only the
        // actor is checked (the resource mock would report it missing).
        let state = state_with(vec![
            assignment("u-live", "system", AssignmentType::UserSystem),
            assignment("g-gone", "system", AssignmentType::GroupSystem),
        ])
        .await;

        let report = run_once(&state).await.unwrap();

        assert_eq!(report.orphans.len(), 1);
        assert_eq!(report.orphans[0].assignment.actor_id, "g-gone");
        assert_eq!(report.orphans[0].missing, Missing::Actor);
    }

    #[tokio::test]
    async fn test_failed_lookup_is_not_an_orphan() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| {
                Ok(vec![assignment(
                    "u-any",
                    "p-live",
                    AssignmentType::UserProject,
                )])
            });
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(|_, _| {
            Err(
                openstack_keystone_core_types::identity::IdentityProviderError::Driver(
                    "backend down".into(),
                ),
            )
        });
        let mut resource = MockResourceProvider::default();
        resource.expect_get_project().returning(|_, _| Ok(None));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock)
                    .mock_identity(identity)
                    .mock_resource(resource),
            ),
        )
        .await;

        let report = run_once(&state).await.unwrap();

        // The actor lookup failed: only the (really missing) target counts.
        assert_eq!(report.errors, 1);
        assert_eq!(report.errors_by_kind.get(&Kind::User), Some(&1));
        assert_eq!(report.orphans.len(), 1);
        assert_eq!(report.orphans[0].missing, Missing::Target);
    }
}
