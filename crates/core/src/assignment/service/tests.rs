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

//! Unit tests for [`super::AssignmentService`].
//!
//! Split out of `service.rs` to keep the implementation file short. Per-domain
//! target-keyed dispatch, the untargeted fan-out and the reload reactor live in
//! the [`per_domain_dispatch`] and [`reload`] submodules (ADR 0034 "Testing").

use openstack_keystone_core_types::revoke::*;
use openstack_keystone_core_types::role::*;

use super::*;
use crate::assignment::backend::MockAssignmentBackend;
use crate::provider::Provider;
use crate::revoke::MockRevokeProvider;
use crate::role::MockRoleProvider;
use crate::tests::get_mocked_state;

#[path = "tests/per_domain_dispatch.rs"]
mod per_domain_dispatch;
#[path = "tests/reload.rs"]
mod reload;

#[test]
fn target_kind_partitions_every_assignment_type() {
    assert!(matches!(
        target_kind(&AssignmentType::UserDomain),
        TargetKind::Domain
    ));
    assert!(matches!(
        target_kind(&AssignmentType::GroupDomain),
        TargetKind::Domain
    ));
    assert!(matches!(
        target_kind(&AssignmentType::UserProject),
        TargetKind::Project
    ));
    assert!(matches!(
        target_kind(&AssignmentType::GroupProject),
        TargetKind::Project
    ));
    assert!(matches!(
        target_kind(&AssignmentType::UserSystem),
        TargetKind::System
    ));
    assert!(matches!(
        target_kind(&AssignmentType::GroupSystem),
        TargetKind::System
    ));
}

#[tokio::test]
async fn test_crate_grant() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockAssignmentBackend::default();
    backend.expect_create_grant().returning(|_, _| {
        Ok(AssignmentBuilder::default()
            .actor_id("actor")
            .role_id("rid1")
            .target_id("target_id")
            .r#type(AssignmentType::UserProject)
            .build()
            .unwrap())
    });

    let provider = AssignmentService::from_backend(Arc::new(backend));

    assert!(
        provider
            .create_grant(
                &ExecutionContext::internal(&state),
                AssignmentCreate::user_project("actor_id", "target_id", "role_id", false)
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_list_assignments() {
    let state = get_mocked_state(None, None).await;
    let mut backend = MockAssignmentBackend::default();
    backend
        .expect_list_assignments()
        .returning(|_, _| Ok(vec![]));

    let provider = AssignmentService::from_backend(Arc::new(backend));

    assert!(
        provider
            .list_role_assignments(
                &ExecutionContext::internal(&state),
                &RoleAssignmentListParameters {
                    role_id: Some("rid".into()),
                    resolve_implied_roles: false,
                    ..Default::default()
                },
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_list_assignments_include_names() {
    let mut role_mock = MockRoleProvider::default();
    role_mock.expect_list_roles().returning(|_, _| {
        Ok(vec![
            RoleBuilder::default()
                .id("rid1")
                .name("rid1_name")
                .build()
                .unwrap(),
            RoleBuilder::default()
                .id("rid2")
                .name("rid2_name")
                .build()
                .unwrap(),
        ])
    });
    let state = get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
    let mut backend = MockAssignmentBackend::default();
    backend
        .expect_list_assignments()
        .withf(|_, params: &RoleAssignmentListParameters| {
            params.role_id == Some("rid".into()) && params.include_names.is_some_and(|x| x)
        })
        .returning(|_, _| {
            Ok(vec![
                AssignmentBuilder::default()
                    .actor_id("actor")
                    .role_id("rid1")
                    .target_id("target_id")
                    .r#type(AssignmentType::UserProject)
                    .build()
                    .unwrap(),
            ])
        });

    let provider = AssignmentService::from_backend(Arc::new(backend));

    let res = provider
        .list_role_assignments(
            &ExecutionContext::internal(&state),
            &RoleAssignmentListParameters {
                role_id: Some("rid".into()),
                include_names: Some(true),
                resolve_implied_roles: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        res.iter()
            .find(|x| x.role_id == "rid1" && x.role_name == Some("rid1_name".into()))
            .is_some()
    );
}

#[tokio::test]
async fn test_revoke_grant() {
    let mut revoke_mock = MockRevokeProvider::default();
    revoke_mock
        .expect_create_revocation_event()
        .withf(|_, params: &RevocationEventCreate| {
            params.project_id == Some("target_id".into())
                && params.user_id == Some("actor".into())
                && params.role_id == Some("rid1".into())
        })
        .returning(|_, _| Ok(RevocationEvent::default()));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_revoke(revoke_mock)),
    )
    .await;
    let mut backend = MockAssignmentBackend::default();
    let assignment = AssignmentBuilder::default()
        .actor_id("actor")
        .role_id("rid1")
        .target_id("target_id")
        .r#type(AssignmentType::UserProject)
        .build()
        .unwrap();
    let assignment_clone = assignment.clone();
    backend
        .expect_revoke_grant()
        .withf(move |_, params: &Assignment| *params == assignment_clone)
        .returning(|_, _| Ok(()));

    let provider = AssignmentService::from_backend(Arc::new(backend));

    assert!(
        provider
            .revoke_grant(&ExecutionContext::internal(&state), assignment)
            .await
            .is_ok()
    );
}
