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

use openstack_keystone_core_types::assignment::{
    Assignment, AssignmentProviderError, AssignmentType, RoleAssignmentListParameters,
};
use openstack_keystone_core_types::auth::{
    AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
    SecurityContextTestingBuilder, TrustProjectInfo, UserIdentityInfo,
};
use openstack_keystone_core_types::identity::{UserOptions, UserResponse, UserResponseBuilder};
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::{MappingContext, VirtualUser};
use openstack_keystone_core_types::resource::Project;
use openstack_keystone_core_types::role::{RoleRef, RoleRefBuilder};
use openstack_keystone_core_types::token::TokenRestriction;
use openstack_keystone_core_types::trust::Trust;
use std::collections::HashMap;

use crate::assignment::MockAssignmentProvider;
use crate::identity::MockIdentityProvider;
use crate::mapping::MockMappingProvider;
use crate::provider::Provider;
use crate::role::{MockRoleProvider, RoleProviderError};
use crate::tests::get_mocked_state;
use crate::trust::MockTrustProvider;

use super::*;

fn make_user_identity(user_id: impl Into<String>) -> PrincipalInfo {
    let uid = user_id.into();
    let u = UserResponse {
        id: uid.clone(),
        domain_id: "d1".to_string(),
        enabled: true,
        name: "u".to_string(),
        extra: HashMap::new(),
        default_project_id: None,
        federated: None,
        options: UserOptions::default(),
        password_expires_at: None,
    };
    let ui = UserIdentityInfo {
        user_id: uid.clone(),
        user: Some(u),
        user_domain: Some(openstack_keystone_core_types::resource::Domain {
            id: "d1".to_string(),
            description: None,
            enabled: true,
            name: "default".to_string(),
            extra: HashMap::new(),
        }),
        user_groups: Vec::new(),
    };
    PrincipalInfo {
        identity: IdentityInfo::User(ui),
    }
}

fn make_project(pid: impl Into<String>) -> Project {
    let pid = pid.into();
    Project {
        id: pid.clone(),
        domain_id: "d1".to_string(),
        enabled: true,
        name: "p".to_string(),
        description: None,
        is_domain: false,
        parent_id: None,
        extra: HashMap::new(),
    }
}

fn make_project_scope(pid: impl Into<String>) -> ScopeInfo {
    ScopeInfo::Project {
        project: make_project(pid),
        project_domain: openstack_keystone_core_types::resource::Domain {
            id: "d1".to_string(),
            description: None,
            enabled: true,
            name: "default".to_string(),
            extra: HashMap::new(),
        },
    }
}

fn make_domain_scope(did: impl Into<String>) -> ScopeInfo {
    ScopeInfo::Domain(openstack_keystone_core_types::resource::Domain {
        id: did.into(),
        description: None,
        enabled: true,
        name: "default".to_string(),
        extra: HashMap::new(),
    })
}

fn make_trust_scope(
    trustor: impl Into<String>,
    trustee: impl Into<String>,
    project: &str,
    roles: Option<Vec<RoleRef>>,
) -> ScopeInfo {
    ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
        trust: Trust {
            id: "t1".to_string(),
            trustor_user_id: trustor.into(),
            trustee_user_id: trustee.into(),
            impersonation: false,
            project_id: None,
            expires_at: None,
            deleted_at: None,
            extra: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles,
        },
        project: make_project(project),
        project_domain: openstack_keystone_core_types::resource::Domain {
            id: "d1".to_string(),
            description: None,
            enabled: true,
            name: "default".to_string(),
            extra: HashMap::new(),
        },
    }))
}

fn assignment_with_role(rid: impl Into<String>) -> Assignment {
    assignment_with_role_actor(rid, "uid")
}

fn assignment_with_role_actor(rid: impl Into<String>, actor: impl Into<String>) -> Assignment {
    Assignment {
        actor_id: actor.into(),
        role_id: rid.into(),
        role_name: Some("admin".to_string()),
        target_id: "target".to_string(),
        r#type: AssignmentType::UserProject,
        inherited: false,
        implied_via: None,
    }
}

fn role_ref(id: impl Into<String>, name: impl Into<String>) -> RoleRef {
    RoleRefBuilder::default().id(id).name(name).build().unwrap()
}

fn role_ref_with_domain(
    id: impl Into<String>,
    name: impl Into<String>,
    domain_id: Option<String>,
) -> RoleRef {
    let mut r = RoleRefBuilder::default().id(id).name(name).build().unwrap();
    r.domain_id = domain_id;
    r
}

fn disabled_domain_scope(did: impl Into<String>) -> ScopeInfo {
    ScopeInfo::Domain(openstack_keystone_core_types::resource::Domain {
        id: did.into(),
        description: None,
        enabled: false,
        name: "disabled".to_string(),
        extra: HashMap::new(),
    })
}

fn disabled_project_scope(pid: impl Into<String>) -> ScopeInfo {
    ScopeInfo::Project {
        project: Project {
            id: pid.into(),
            domain_id: "d1".to_string(),
            enabled: false,
            name: "p".to_string(),
            description: None,
            is_domain: false,
            parent_id: None,
            extra: HashMap::new(),
        },
        project_domain: openstack_keystone_core_types::resource::Domain {
            id: "d1".to_string(),
            description: None,
            enabled: true,
            name: "default".to_string(),
            extra: HashMap::new(),
        },
    }
}

fn disabled_project_domain_scope(pid: impl Into<String>) -> ScopeInfo {
    ScopeInfo::Project {
        project: Project {
            id: pid.into(),
            domain_id: "d1".to_string(),
            enabled: true,
            name: "p".to_string(),
            description: None,
            is_domain: false,
            parent_id: None,
            extra: HashMap::new(),
        },
        project_domain: openstack_keystone_core_types::resource::Domain {
            id: "d1".to_string(),
            description: None,
            enabled: false,
            name: "disabled".to_string(),
            extra: HashMap::new(),
        },
    }
}

fn disabled_trust_scope(
    trustor: impl Into<String>,
    trustee: impl Into<String>,
    project: &str,
    roles: Option<Vec<RoleRef>>,
) -> ScopeInfo {
    ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
        trust: Trust {
            id: "t1".to_string(),
            trustor_user_id: trustor.into(),
            trustee_user_id: trustee.into(),
            impersonation: false,
            project_id: None,
            expires_at: None,
            deleted_at: None,
            extra: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles,
        },
        project: Project {
            id: project.to_string(),
            domain_id: "d1".to_string(),
            enabled: false,
            name: "p".to_string(),
            description: None,
            is_domain: false,
            parent_id: None,
            extra: HashMap::new(),
        },
        project_domain: openstack_keystone_core_types::resource::Domain {
            id: "d1".to_string(),
            description: None,
            enabled: true,
            name: "default".to_string(),
            extra: HashMap::new(),
        },
    }))
}

fn disabled_trust_project_domain_scope(
    trustor: impl Into<String>,
    trustee: impl Into<String>,
    project: &str,
    roles: Option<Vec<RoleRef>>,
) -> ScopeInfo {
    ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
        trust: Trust {
            id: "t1".to_string(),
            trustor_user_id: trustor.into(),
            trustee_user_id: trustee.into(),
            impersonation: false,
            project_id: None,
            expires_at: None,
            deleted_at: None,
            extra: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles,
        },
        project: Project {
            id: project.to_string(),
            domain_id: "d1".to_string(),
            enabled: true,
            name: "p".to_string(),
            description: None,
            is_domain: false,
            parent_id: None,
            extra: HashMap::new(),
        },
        project_domain: openstack_keystone_core_types::resource::Domain {
            id: "d1".to_string(),
            description: None,
            enabled: false,
            name: "disabled".to_string(),
            extra: HashMap::new(),
        },
    }))
}

#[tokio::test]
async fn test_unscoped_returns_empty() {
    let state = get_mocked_state(None, None).await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .build();
    let scope = ScopeInfo::Unscoped;
    let roles = calculate_effective_roles(&state, &ctx, &scope).await;
    assert_eq!(roles.unwrap(), Vec::<RoleRef>::new());
}

#[tokio::test]
async fn test_project_scope_returns_assignment_roles() {
    let uid = "uid";
    let pid = "pid";
    let rid1 = "rid1";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
                && q.domain_id.is_none()
                && q.system_id.is_none()
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(rid1)]));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = make_project_scope(pid);
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, rid1);
}

#[tokio::test]
async fn test_domain_scope_returns_assignment_roles() {
    let uid = "uid";
    let did = "did";
    let rid1 = "rid1";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.domain_id.as_deref() == Some(did)
                && q.effective == Some(true)
                && q.include_names == Some(true)
                && q.project_id.is_none()
                && q.system_id.is_none()
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(rid1)]));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = make_domain_scope(did);
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, rid1);
}

#[tokio::test]
async fn test_system_scope_returns_assignment_roles() {
    let uid = "uid";
    let system = "all";
    let rid1 = "rid1";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.system_id.as_deref() == Some(system)
                && q.effective == Some(true)
                && q.include_names == Some(true)
                && q.domain_id.is_none()
                && q.project_id.is_none()
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(rid1)]));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = ScopeInfo::System(system.to_string());
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, rid1);
}

#[tokio::test]
async fn test_trust_scope_with_roles() {
    let trustor = "trustor";
    let pid = "pid";
    let rid1 = "rid1";
    let trust_roles = vec![role_ref(rid1, "admin")];
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(rid1)]));
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(|_e, _roles| Ok(()));
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock),
        ),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, rid1);
}

#[tokio::test]
async fn test_trust_scope_without_roles() {
    let trustor = "trustor";
    let pid = "pid";
    let rid1 = "rid1";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role("rid1")]));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, None);
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, rid1);
}

#[tokio::test]
async fn test_project_scope_with_token_restriction() {
    let rid1 = "rid1";
    let restriction_roles = vec![role_ref(rid1, "admin")];
    let tr = TokenRestriction {
        id: "tr1".to_string(),
        domain_id: "d1".to_string(),
        allow_rescope: true,
        allow_renew: false,
        role_ids: vec![rid1.to_string()],
        roles: Some(restriction_roles.clone()),
        project_id: Some("pid".to_string()),
        user_id: Some("uid".to_string()),
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .token_restriction(tr)
        .build();
    let state = get_mocked_state(None, None).await;
    let scope = make_project_scope("pid");
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles, restriction_roles);
}

#[tokio::test]
async fn test_project_scope_appcred_filters_missing_role() {
    let uid = "uid";
    let pid = "pid";
    let admin_rid = "admin";
    let viewer_rid = "viewer";
    let appcred_roles = vec![role_ref(admin_rid, "admin"), role_ref(viewer_rid, "viewer")];
    // User only has admin assigned
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(admin_rid)]));
    let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
        id: "ac1".to_string(),
        user_id: uid.to_string(),
        project_id: pid.to_string(),
        name: "cred".to_string(),
        description: None,
        roles: appcred_roles,
        unrestricted: false,
        expires_at: None,
        access_rules: None,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::ApplicationCredential {
            application_credential: ac,
            token: None,
        })
        .principal(make_user_identity(uid))
        .build();
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let scope = make_project_scope(pid);
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, admin_rid);
}

#[tokio::test]
async fn test_project_scope_token_restriction_expand_role_ids() {
    let rid1 = "rid1";
    let rid2 = "rid2";
    let tr = TokenRestriction {
        id: "tr1".to_string(),
        domain_id: "d1".to_string(),
        allow_rescope: true,
        allow_renew: false,
        role_ids: vec![rid1.to_string(), rid2.to_string()],
        roles: None,
        project_id: Some("pid".to_string()),
        user_id: Some("uid".to_string()),
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .token_restriction(tr)
        .build();
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .withf(move |_e, roles| roles.len() == 2 && roles.iter().any(|r| r.id == rid1))
        .returning(move |_e, roles| {
            for role in roles.iter_mut() {
                if role.id == rid1 {
                    role.name = Some("admin".to_string());
                }
            }
            Ok(())
        });
    let state = get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
    let scope = make_project_scope("pid");
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 2);
    assert!(roles.iter().any(|r| r.id == rid1));
    assert!(roles.iter().any(|r| r.id == rid2));
}

#[tokio::test]
async fn test_trust_scope_missing_role_error() {
    let trustor = "trustor";
    let pid = "pid";
    let trust_rid = "trust_role";
    let trustor_rid = "other_role";
    let trust_roles = vec![role_ref(trust_rid, "trustadmin")];
    // Trustor has a different role, not the one on the trust
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(trustor_rid)]));
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(|_e, _roles| Ok(()));
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock),
        ),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

#[tokio::test]
async fn test_trust_scope_filters_domain_roles() {
    let trustor = "trustor";
    let pid = "pid";
    let rid1 = "rid1";
    let rid2 = "rid2";
    let trust_roles = vec![
        role_ref_with_domain(rid1, "admin", None),
        role_ref_with_domain(rid2, "domain_admin", Some("d1".to_string())),
    ];
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(rid1), assignment_with_role(rid2)]));
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(|_e, _roles| Ok(()));
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock),
        ),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, rid1);
}

#[tokio::test]
async fn test_domain_scope_empty_assignments_error() {
    let uid = "uid";
    let did = "did";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.domain_id.as_deref() == Some(did)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Ok(Vec::<Assignment>::new()));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = make_domain_scope(did);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

#[tokio::test]
async fn test_domain_scope_disabled_error() {
    let did = "did";
    let state = get_mocked_state(None, None).await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .build();
    let scope = disabled_domain_scope(did);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    match result.unwrap_err() {
        //result,
        //Err(AuthenticationError::DomainDisabled(id))
        AuthenticationError::DomainDisabled(id) if id == did => {}
        e => panic!("unexpected error: {:?}", e),
    };
}

#[tokio::test]
async fn test_project_scope_disabled_error() {
    let pid = "pid";
    let state = get_mocked_state(None, None).await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .build();
    let scope = disabled_project_scope(pid);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    match result.unwrap_err() {
        //result,
        //Err(AuthenticationError::ProjectDisabled(id))
        AuthenticationError::ProjectDisabled(id) if id == pid => {}
        e => panic!("unexpected error: {:?}", e),
    };
}

#[tokio::test]
async fn test_project_scope_disabled_domain_error() {
    let pid = "pid";
    let state = get_mocked_state(None, None).await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .build();
    let scope = disabled_project_domain_scope(pid);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    match result.unwrap_err() {
        //result,
        //Err(AuthenticationError::DomainDisabled(id))
        AuthenticationError::DomainDisabled(id) if id == "d1" => {}
        e => panic!("unexpected error: {:?}", e),
    };
}

#[tokio::test]
async fn test_trust_scope_disabled_project_error() {
    let state = get_mocked_state(None, None).await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("trustor"))
        .build();
    let scope = disabled_trust_scope("trustor", "trustee", "pid", None);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    match result.unwrap_err() {
        //result,
        //Err(AuthenticationError::ProjectDisabled(id))
        AuthenticationError::ProjectDisabled(id) if id == "pid" => {}
        e => panic!("unexpected error: {:?}", e),
    };
}

#[tokio::test]
async fn test_trust_scope_disabled_domain_error() {
    let state = get_mocked_state(None, None).await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("trustor"))
        .build();
    let scope = disabled_trust_project_domain_scope("trustor", "trustee", "pid", None);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    match result.unwrap_err() {
        // result,
        //Err(AuthenticationError::DomainDisabled(id))
        AuthenticationError::DomainDisabled(id) if id == "d1" => {}
        e => panic!("unexpected error: {:?}", e),
    };
}

// --- Project scope empty assignments error ---
#[tokio::test]
async fn test_project_scope_empty_assignments_error() {
    let uid = "uid";
    let pid = "pid";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Ok(Vec::<Assignment>::new()));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = make_project_scope(pid);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- System scope empty assignments error ---
#[tokio::test]
async fn test_system_scope_empty_assignments_error() {
    let uid = "uid";
    let system = "all";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.system_id.as_deref() == Some(system)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Ok(Vec::<Assignment>::new()));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = ScopeInfo::System(system.to_string());
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- AppCred: all roles pass filter ---
#[tokio::test]
async fn test_project_scope_appcred_all_roles_pass() {
    let uid = "uid";
    let pid = "pid";
    let admin_rid = "admin";
    let viewer_rid = "viewer";
    let appcred_roles = vec![role_ref(admin_rid, "admin"), role_ref(viewer_rid, "viewer")];
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| {
            Ok(vec![
                assignment_with_role(admin_rid),
                assignment_with_role(viewer_rid),
            ])
        });
    let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
        id: "ac1".to_string(),
        user_id: uid.to_string(),
        project_id: pid.to_string(),
        name: "cred".to_string(),
        description: None,
        roles: appcred_roles,
        unrestricted: false,
        expires_at: None,
        access_rules: None,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::ApplicationCredential {
            application_credential: ac,
            token: None,
        })
        .principal(make_user_identity(uid))
        .build();
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let scope = make_project_scope(pid);
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 2);
    assert!(roles.iter().any(|r| r.id == admin_rid));
    assert!(roles.iter().any(|r| r.id == viewer_rid));
}

// --- Token restriction: roles: Some(empty) returns empty ---
#[tokio::test]
async fn test_project_scope_token_restriction_empty_roles() {
    let tr = TokenRestriction {
        id: "tr1".to_string(),
        domain_id: "d1".to_string(),
        allow_rescope: true,
        allow_renew: false,
        role_ids: vec!["rid1".to_string()],
        roles: Some(Vec::new()),
        project_id: Some("pid".to_string()),
        user_id: Some("uid".to_string()),
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .token_restriction(tr)
        .build();
    let state = get_mocked_state(None, None).await;
    let scope = make_project_scope("pid");
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

#[tokio::test]
async fn test_new_for_scope_explicit_empty_roles_error() {
    let uid = "uid";
    let pid = "pid";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![]));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let authz = AuthzInfoBuilder::default()
        .scope(make_project_scope(pid))
        .roles(Vec::new())
        .build()
        .unwrap();
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .authorization(authz)
        .build();
    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- Trust scope: expand_implied_roles adds an implied role, trustor has it
// ---
#[tokio::test]
async fn test_trust_scope_implied_role_expansion() {
    let trustor = "trustor";
    let pid = "pid";
    let base_rid = "base_role";
    let implied_rid = "implied_role";
    let trust_roles = vec![role_ref(base_rid, "base")];
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| {
            Ok(vec![
                assignment_with_role_actor(base_rid, trustor),
                assignment_with_role_actor(implied_rid, trustor),
            ])
        });
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(move |_e, roles| {
            roles.push(role_ref(implied_rid, "implied"));
            Ok(())
        });
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock),
        ),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
    let roles = calculate_effective_roles(&state, &ctx, &scope)
        .await
        .unwrap();
    assert_eq!(roles.len(), 2);
    assert!(roles.iter().any(|r| r.id == base_rid));
    assert!(roles.iter().any(|r| r.id == implied_rid));
}

// --- Provider error: domain scope list_role_assignments ---
#[tokio::test]
async fn test_domain_scope_provider_error() {
    let uid = "uid";
    let did = "did";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.domain_id.as_deref() == Some(did)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Err(AssignmentProviderError::Driver("db down".into())));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = make_domain_scope(did);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
}

// --- Provider error: project scope list_role_assignments ---
#[tokio::test]
async fn test_project_scope_provider_error() {
    let uid = "uid";
    let pid = "pid";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Err(AssignmentProviderError::Driver("db down".into())));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = make_project_scope(pid);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
}

// --- Provider error: system scope list_role_assignments ---
#[tokio::test]
async fn test_system_scope_provider_error() {
    let uid = "uid";
    let system = "all";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.system_id.as_deref() == Some(system)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Err(AssignmentProviderError::Driver("db down".into())));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .build();
    let scope = ScopeInfo::System(system.to_string());
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
}

// --- Provider error: trust scope list_role_assignments ---
#[tokio::test]
async fn test_trust_scope_provider_error() {
    let trustor = "trustor";
    let pid = "pid";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Err(AssignmentProviderError::Driver("db down".into())));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, None);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
}

// --- Provider error: trust expand_implied_roles ---
#[tokio::test]
async fn test_trust_scope_expand_implied_error() {
    let trustor = "trustor";
    let pid = "pid";
    let trust_rid = "trust_role";
    let trust_roles = vec![role_ref(trust_rid, "trustadmin")];
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(trust_rid)]));
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(move |_e, _roles| Err(RoleProviderError::Driver("db down".into())));
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock),
        ),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
}

// --- Provider error: token restriction expand_implied_roles ---
#[tokio::test]
async fn test_project_scope_token_restriction_expand_error() {
    let rid1 = "rid1";
    let tr = TokenRestriction {
        id: "tr1".to_string(),
        domain_id: "d1".to_string(),
        allow_rescope: true,
        allow_renew: false,
        role_ids: vec![rid1.to_string()],
        roles: None,
        project_id: Some("pid".to_string()),
        user_id: Some("uid".to_string()),
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .token_restriction(tr)
        .build();
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(move |_e, _roles| Err(RoleProviderError::Driver("db".into())));
    let state = get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
    let scope = make_project_scope("pid");
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
}

// --- AppCred: empty roles list returns empty after filter ---
#[tokio::test]
async fn test_project_scope_appcred_empty_roles() {
    let uid = "uid";
    let pid = "pid";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role("admin")]));
    let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
        id: "ac1".to_string(),
        user_id: uid.to_string(),
        project_id: pid.to_string(),
        name: "cred".to_string(),
        description: None,
        roles: Vec::new(),
        unrestricted: false,
        expires_at: None,
        access_rules: None,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::ApplicationCredential {
            application_credential: ac,
            token: None,
        })
        .principal(make_user_identity(uid))
        .build();
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let scope = make_project_scope(pid);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- AppCred: all credential roles missing after filter ---
#[tokio::test]
async fn test_project_scope_appcred_all_roles_missing() {
    let uid = "uid";
    let pid = "pid";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role("admin")]));
    let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
        id: "ac1".to_string(),
        user_id: uid.to_string(),
        project_id: pid.to_string(),
        name: "cred".to_string(),
        description: None,
        roles: vec![role_ref("other", "other")],
        unrestricted: false,
        expires_at: None,
        access_rules: None,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::ApplicationCredential {
            application_credential: ac,
            token: None,
        })
        .principal(make_user_identity(uid))
        .build();
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let scope = make_project_scope(pid);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- Trust: expand adds role trustor does not have, .all() fails ---
#[tokio::test]
async fn test_trust_scope_expand_adds_missing_role() {
    let trustor = "trustor";
    let pid = "pid";
    let base_rid = "base_role";
    let extra_rid = "extra_role";
    let trust_roles = vec![role_ref(base_rid, "base")];
    // Trustor only has base_role, not extra_role
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role_actor(base_rid, trustor)]));
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(move |_e, roles| {
            roles.push(role_ref(extra_rid, "extra"));
            Ok(())
        });
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock),
        ),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, Some(trust_roles));
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    // After expand, trust_roles includes extra_role, but trustor does not have it
    // .all() check fails -> ActorHasNoRolesOnTarget
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- Trust: no roles, trustor has no assignments ---
#[tokio::test]
async fn test_trust_scope_no_roles_no_assignments() {
    let trustor = "trustor";
    let pid = "pid";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(trustor)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
        })
        .returning(move |_e, _q| Ok(Vec::<Assignment>::new()));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(trustor))
        .build();
    let scope = make_trust_scope(trustor, "trustee", pid, None);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- Token restriction: role_ids empty, roles Some(roles) falls through ---
#[tokio::test]
async fn test_project_scope_token_restriction_no_role_ids_fallthrough() {
    let uid = "uid";
    let pid = "pid";
    let restriction_roles = vec![role_ref("restricted", "restricted")];
    let tr = TokenRestriction {
        id: "tr1".to_string(),
        domain_id: "d1".to_string(),
        allow_rescope: true,
        allow_renew: false,
        role_ids: Vec::new(),
        roles: Some(restriction_roles.clone()),
        project_id: Some(pid.to_string()),
        user_id: Some(uid.to_string()),
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .token_restriction(tr)
        .build();
    // role_ids is empty so !restriction.role_ids.is_empty() is false
    // Falls through to assignment lookup which returns empty
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
        })
        .returning(move |_e, _q| Ok(Vec::<Assignment>::new()));
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;
    let scope = make_project_scope(pid);
    let result = calculate_effective_roles(&state, &ctx, &scope).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

/// `populate_user_domain` must actually populate the field: `validate()`
/// (called immediately after, per the comment "Populate user_domain
/// before validation, since validate() requires it") fails closed when
/// a `UserIdentityInfo` has no `user_domain`, so a no-op here would
/// surface as the whole request being rejected, not silently
/// succeeding with a missing domain. Catches the function body being
/// replaced with `()`.
#[tokio::test]
async fn test_new_for_scope_populates_missing_user_domain_from_resource_provider() {
    use crate::resource::MockResourceProvider;

    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_get_domain()
        .withf(|_e, domain_id: &str| domain_id == "d1")
        .returning(|_e, id| {
            Ok(Some(openstack_keystone_core_types::resource::Domain {
                id: id.to_string(),
                name: "d1".to_string(),
                enabled: true,
                ..Default::default()
            }))
        });

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_resource(resource_mock)),
    )
    .await;

    let user = UserResponseBuilder::default()
        .id("uid")
        .domain_id("d1")
        .enabled(true)
        .name("uid")
        .build()
        .unwrap();
    let principal = PrincipalInfo {
        identity: IdentityInfo::User(UserIdentityInfo {
            user_id: "uid".to_string(),
            user: Some(user),
            user_domain: None,
            user_groups: Vec::new(),
        }),
    };

    let authz = AuthzInfoBuilder::default()
        .scope(ScopeInfo::Unscoped)
        .roles(Vec::new())
        .build()
        .unwrap();
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(principal)
        .authorization(authz)
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;

    let validated =
        result.expect("user_domain should have been populated, allowing validate() to succeed");
    match &validated.0.principal().identity {
        IdentityInfo::User(ui) => {
            assert_eq!(ui.user_domain.as_ref().map(|d| d.id.as_str()), Some("d1"));
        }
        _ => panic!("expected a User identity"),
    }
}

// Unscoped scope must succeed with zero effective roles.  The assignment
// provider must never be called (no mock needed).
#[tokio::test]
async fn test_new_for_scope_unscoped_success() {
    let state = get_mocked_state(None, None).await;
    // Build a context that already carries an Unscoped authorization so the
    // scope-boundary check is skipped entirely (scopes are equal).
    let authz = AuthzInfoBuilder::default()
        .scope(ScopeInfo::Unscoped)
        .roles(Vec::new())
        .build()
        .unwrap();
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .authorization(authz)
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;

    // Must succeed and carry zero effective roles — the Unscoped path in
    // calculate_effective_roles returns Vec::new() and skips the
    // ActorHasNoRolesOnTarget guard.
    let validated = result.unwrap();

    // Access the roles via the authorization state getter
    let roles = validated.0.authorization().unwrap().effective_roles();
    assert!(roles.is_none() || roles.unwrap().is_empty());
}

// A context whose expires_at is in the past must fail with
// AuthTokenExpired before any role/scope checks run.
#[tokio::test]
async fn test_new_for_scope_expired_token_fails() {
    let state = get_mocked_state(None, None).await;
    let authz = AuthzInfoBuilder::default()
        .scope(ScopeInfo::Unscoped)
        .roles(Vec::new())
        .build()
        .unwrap();
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .authorization(authz)
        .expires_at(Utc::now() - chrono::Duration::seconds(60))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;

    assert!(matches!(result, Err(AuthenticationError::AuthTokenExpired)));
}

// Project-scoped context with a live assignment must succeed and surface
// exactly that one role as an effective role.
#[tokio::test]
async fn test_new_for_scope_project_scoped_success() {
    let uid = "uid";
    let pid = "pid";
    let rid = "admin_role";

    // Strict predicate: must be called once for this user+project combination
    // with the exact flags used by resolve_project_default_roles.
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
                && q.domain_id.is_none()
                && q.system_id.is_none()
        })
        .returning(move |_e, _q| Ok(vec![assignment_with_role(rid)]));

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;

    // Pre-set the same project scope so the boundary check is skipped.
    let authz = AuthzInfoBuilder::default()
        .scope(make_project_scope(pid))
        .roles(Vec::new())
        .build()
        .unwrap();
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .authorization(authz)
        .build();

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

    // Must succeed; effective roles must contain exactly the one role the
    // assignment provider returned.
    let validated = result.unwrap();

    // Access the roles via the authorization state getter
    let roles = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, rid);
}

// Project-scoped context where the assignment provider returns nothing must
// fail with ActorHasNoRolesOnTarget.
#[tokio::test]
async fn test_new_for_scope_project_scoped_no_roles_fails() {
    let uid = "uid";
    let pid = "pid";

    // Same strict predicate as Test 2 — the provider IS called but returns
    // an empty list, triggering the ActorHasNoRolesOnTarget guard.
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(|_, q: &RoleAssignmentListParameters| {
            q.user_id.as_deref() == Some(uid)
                && q.project_id.as_deref() == Some(pid)
                && q.effective == Some(true)
                && q.include_names == Some(true)
                && q.domain_id.is_none()
                && q.system_id.is_none()
        })
        .returning(|_, _| Ok(Vec::<Assignment>::new()));

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;

    let authz = AuthzInfoBuilder::default()
        .scope(make_project_scope(pid))
        .roles(Vec::new())
        .build()
        .unwrap();
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .authorization(authz)
        .build();

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

    // calculate_effective_roles sees an empty, non-Unscoped result and must
    // return ActorHasNoRolesOnTarget.
    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// Companion positive case: an admin principal with no roles on the
// target scope must NOT trip `ActorHasNoRolesOnTarget` — `is_admin`
// bypasses the check. Catches `delete !` on `!ctx.is_admin()`.
#[tokio::test]
async fn test_new_for_scope_admin_with_no_roles_on_target_is_allowed() {
    let uid = "uid";
    let pid = "pid";

    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(|_, _| Ok(Vec::<Assignment>::new()));

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_assignment(assignment_mock)),
    )
    .await;

    let authz = AuthzInfoBuilder::default()
        .scope(make_project_scope(pid))
        .roles(Vec::new())
        .build()
        .unwrap();
    let mut ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity(uid))
        .authorization(authz)
        .build();
    ctx.set_is_admin();

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

    assert!(result.is_ok());
}

/// The `AuthenticationContext::Admin` fast path in
/// `resolve_system_roles` grants a hardcoded "reader" role set
/// instead of resolving the caller's actual assignments; assert the
/// query sent to `list_roles` actually filters by that name. Catches
/// the `name: Some("reader".into())` field being deleted from the
/// query, which would silently list (and grant) every role instead
/// of just "reader".
#[tokio::test]
async fn test_resolve_system_roles_admin_context_filters_by_reader_role_name() {
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_list_roles()
        .withf(|_e, params: &RoleListParameters| params.name.as_deref() == Some("reader"))
        .returning(|_e, _params| {
            Ok(vec![
                openstack_keystone_core_types::role::RoleBuilder::default()
                    .id("role-1")
                    .name("reader")
                    .build()
                    .unwrap(),
            ])
        });

    let state = get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Admin)
        .principal(make_user_identity("uid"))
        .build();

    let roles = resolve_system_roles(&state, &ctx, "all").await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name.as_deref(), Some("reader"));
}

/// `correlation_id()` returns whatever was attached via
/// `set_correlation_id`, and falls back to `"unknown"` (never panics or
/// returns an empty string) when none was ever set -- used by
/// `audited_op!` to stamp the compensating local log when the
/// post-audit critical channel is full.
#[test]
fn correlation_id_reflects_set_value_and_falls_back_to_unknown() {
    let mut ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .build();
    ctx.set_correlation_id("req-42");
    let vsc = ValidatedSecurityContext::test_new(ctx);
    assert_eq!(vsc.correlation_id(), "req-42");

    let ctx_without_correlation_id = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .build();
    let vsc_without_correlation_id = ValidatedSecurityContext::test_new(ctx_without_correlation_id);
    assert_eq!(vsc_without_correlation_id.correlation_id(), "unknown");
}

// --- Mapping: domain scope match returns pre-populated roles ---
#[tokio::test]
async fn test_new_for_scope_mapping_domain_scope_match() {
    let did = "domain-1";
    let vir_id = "vu-1234567890abcdef1234567890abcdef";
    let rid = "admin";
    let roles = vec![role_ref(rid, "admin")];

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-1".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        domain_id: Some(did.to_string()),
        resolved_user_name: "mapped_user".to_string(),
        is_system: false,
        resolved_group_bindings: vec![],
        authorizations: vec![Authorization::Domain {
            domain_id: did.to_string(),
            roles: roles.clone(),
        }],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: false,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, make_domain_scope(did), &state).await;

    let validated = result.unwrap();
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// --- Mapping: project scope match returns pre-populated roles ---
#[tokio::test]
async fn test_new_for_scope_mapping_project_scope_match() {
    let pid = "project-1";
    let vir_id = "vu-abcdef1234567890abcdef1234567890";
    let rid = "reader";
    let roles = vec![role_ref(rid, "reader")];

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-2".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        domain_id: Some("d1".to_string()),
        resolved_user_name: "mapped_user".to_string(),
        is_system: false,
        resolved_group_bindings: vec![],
        authorizations: vec![Authorization::Project {
            project_id: pid.to_string(),
            project_domain_id: "d1".to_string(),
            roles: roles.clone(),
        }],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: false,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

    let validated = result.unwrap();
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// --- Mapping: system scope match returns pre-populated roles ---
#[tokio::test]
async fn test_new_for_scope_mapping_system_scope_match() {
    let sys = "all";
    let vir_id = "vu-11111111111111111111111111111111";
    let rid = "admin";
    let roles = vec![role_ref(rid, "admin")];

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-3".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        domain_id: None,
        resolved_user_name: "mapped_user".to_string(),
        is_system: false,
        resolved_group_bindings: vec![],
        authorizations: vec![Authorization::System {
            system_id: sys.to_string(),
            roles: roles.clone(),
        }],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: false,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::System(sys.to_string()), &state)
            .await;

    let validated = result.unwrap();
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// --- Mapping: scope mismatch (no matching authorization) fails ---
#[tokio::test]
async fn test_new_for_scope_mapping_scope_mismatch() {
    let vir_id = "vu-aabbccdd11223344aabbccdd11223344";

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-4".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        domain_id: Some("d1".to_string()),
        resolved_user_name: "mapped_user".to_string(),
        is_system: false,
        resolved_group_bindings: vec![],
        // Authorization for a different project, so requested scope won't match
        authorizations: vec![Authorization::Project {
            project_id: "other-project".to_string(),
            project_domain_id: "d1".to_string(),
            roles: vec![role_ref("reader", "reader")],
        }],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    // Assignment fallback is triggered since no matching authorization
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(|_, _| Ok(Vec::<Assignment>::new()));

    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_mapping(mapping_mock)
                .mock_assignment(assignment_mock),
        ),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: false,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(
        ctx,
        make_project_scope("requested-project"),
        &state,
    )
    .await;

    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- Mapping: virtual user not found fails ---
#[tokio::test]
async fn test_new_for_scope_mapping_virtual_user_not_found() {
    let vir_id = "vu-nonexistent0000000000000000000000";

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, _| Ok(None::<VirtualUser>));

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: false,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope("pid"), &state).await;

    assert!(matches!(result, Err(AuthenticationError::Provider { .. })));
}

// --- Mapping: empty authorizations list fails ---
#[tokio::test]
async fn test_new_for_scope_mapping_empty_authorizations() {
    let vir_id = "vu-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-5".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        domain_id: Some("d1".to_string()),
        resolved_user_name: "mapped_user".to_string(),
        is_system: false,
        resolved_group_bindings: vec![],
        authorizations: vec![],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    // Assignment fallback is triggered since no matching authorization
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(|_, _| Ok(Vec::<Assignment>::new()));

    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_mapping(mapping_mock)
                .mock_assignment(assignment_mock),
        ),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: false,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope("pid"), &state).await;

    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- Mapping: is_system with Unscoped → System("all") scope override ---
#[tokio::test]
async fn test_new_for_scope_mapping_is_system_unscoped_override() {
    let vir_id = "vu-system00000000000000000000000000";
    let rid = "admin";
    let roles = vec![role_ref(rid, "admin")];

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-sys".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "system-rule".to_string(),
        domain_id: None,
        resolved_user_name: "system-user".to_string(),
        is_system: true,
        resolved_group_bindings: vec![],
        authorizations: vec![Authorization::System {
            system_id: "all".to_string(),
            roles: roles.clone(),
        }],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "system-rule".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: true,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    // Pass Unscoped - is_system should override to System("all")
    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;

    let validated = result.unwrap();
    // Verify scope was upgraded to System
    assert!(matches!(
        validated.0.authorization().unwrap().scope,
        ScopeInfo::System(ref s) if s == "all"
    ));
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// --- Mapping: is_system with Unscoped and no matching System authorization
// fails ---
#[tokio::test]
async fn test_new_for_scope_mapping_is_system_no_system_auth() {
    let vir_id = "vu-system00000000000000000000000001";

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-sys-2".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "system-rule".to_string(),
        domain_id: None,
        resolved_user_name: "system-user".to_string(),
        is_system: true,
        resolved_group_bindings: vec![],
        // Authorization for a domain, not system - mismatch after override
        authorizations: vec![Authorization::Domain {
            domain_id: "d1".to_string(),
            roles: vec![role_ref("reader", "reader")],
        }],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    // Assignment fallback is triggered since no System authorization matches
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(|_, _| Ok(Vec::<Assignment>::new()));

    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_mapping(mapping_mock)
                .mock_assignment(assignment_mock),
        ),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "system-rule".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: true,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    // Pass Unscoped - is_system overrides to System, but no system auth matches
    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;

    assert!(matches!(
        result,
        Err(AuthenticationError::ActorHasNoRolesOnTarget)
    ));
}

// --- Mapping fast path: pre-set project authorization skips storage read ---
#[tokio::test]
async fn test_new_for_scope_mapping_fast_path_project() {
    let pid = "project-1";
    let vir_id = "vu-fast-path-project-0000000000000000";
    let rid = "admin";
    let roles = vec![role_ref(rid, "admin")];

    let authz = AuthzInfoBuilder::default()
        .scope(make_project_scope(pid))
        .roles(roles.clone())
        .build()
        .unwrap();

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: false,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .authorization(authz)
        .build();

    // No mock mapping provider — get_virtual_user must NOT be called
    let state = get_mocked_state(None, None).await;

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

    let validated = result.unwrap();
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// --- Mapping fast path: is_system upgrade with pre-set system roles skips
// storage read ---
#[tokio::test]
async fn test_new_for_scope_mapping_fast_path_system_unscoped_upgrade() {
    let vir_id = "vu-fast-path-system-0000000000000000";
    let rid = "admin";
    let roles = vec![role_ref(rid, "admin")];

    let authz = AuthzInfoBuilder::default()
        .scope(ScopeInfo::System("all".into()))
        .roles(roles.clone())
        .build()
        .unwrap();

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "system-rule".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: true,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .authorization(authz)
        .build();

    // No mock mapping provider — get_virtual_user must NOT be called
    let state = get_mocked_state(None, None).await;

    // Pass Unscoped — is_system with pre-set roles should upgrade to
    // System("all") without storage read
    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;

    let validated = result.unwrap();
    assert!(matches!(
        validated.0.authorization().unwrap().scope,
        ScopeInfo::System(ref s) if s == "all"
    ));
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// Discriminates `is_system && matches!(scope_clone, ScopeInfo::Unscoped)`
// (the fast-path upgrade guard): `is_system` alone must never upgrade a
// non-Unscoped target scope to System. Catches `&&` -> `||`.
#[tokio::test]
async fn test_new_for_scope_mapping_fast_path_is_system_true_project_not_upgraded() {
    let pid = "project-2";
    let vir_id = "vu-fast-path-system-project-0000000000000000";
    let rid = "member";
    let roles = vec![role_ref(rid, "member")];

    let authz = AuthzInfoBuilder::default()
        .scope(make_project_scope(pid))
        .roles(roles.clone())
        .build()
        .unwrap();

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: true,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .authorization(authz)
        .build();

    // No mock mapping provider — get_virtual_user must NOT be called
    let state = get_mocked_state(None, None).await;

    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

    let validated = result.unwrap();
    assert!(matches!(
        validated.0.authorization().unwrap().scope,
        ScopeInfo::Project { .. }
    ));
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// --- Mapping fast path: pre-set domain roles skip storage read ---
#[tokio::test]
async fn test_new_for_scope_mapping_fast_path_domain() {
    let did = "domain-1";
    let vir_id = "vu-fast-path-domain-0000000000000000";
    let rid = "reader";
    let roles = vec![role_ref(rid, "reader")];

    let authz = AuthzInfoBuilder::default()
        .scope(make_domain_scope(did))
        .roles(roles.clone())
        .build()
        .unwrap();

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: false,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .authorization(authz)
        .build();

    // No mock mapping provider — get_virtual_user must NOT be called
    let state = get_mocked_state(None, None).await;

    let result = ValidatedSecurityContext::new_for_scope(ctx, make_domain_scope(did), &state).await;

    let validated = result.unwrap();
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// --- Mapping slow path: is_system true, unscoped scope, no pre-set auth,
// reads virtual user from storage ---
#[tokio::test]
async fn test_new_for_scope_mapping_slow_path_system_unscoped() {
    let vir_id = "vu-slow-path-system-0000000000000000";
    let rid = "admin";
    let roles = vec![role_ref(rid, "admin")];

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-sys-slow".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "system-rule".to_string(),
        domain_id: None,
        resolved_user_name: "system-user".to_string(),
        is_system: true,
        resolved_group_bindings: vec![],
        authorizations: vec![Authorization::System {
            system_id: "all".to_string(),
            roles: roles.clone(),
        }],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "system-rule".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: true,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    // No pre-set authorization — slow path with storage read
    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;

    let validated = result.unwrap();
    assert!(matches!(
        validated.0.authorization().unwrap().scope,
        ScopeInfo::System(ref s) if s == "all"
    ));
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// Discriminates `is_system && matches!(scope_clone, ScopeInfo::Unscoped)`
// in the no-prepopulated-roles branch: `is_system` alone must not divert
// a Project-scoped request onto the system-upgrade/slow-read path.
// Catches `&&` -> `||`.
#[tokio::test]
async fn test_new_for_scope_mapping_slow_path_is_system_true_project_not_upgraded() {
    let pid = "project-3";
    let vir_id = "vu-slow-path-system-project-0000000000000000";
    let rid = "member";
    let roles = vec![role_ref(rid, "member")];

    let vu = VirtualUser {
        user_id: vir_id.to_string(),
        unique_workload_id: "workload-sys-project-slow".to_string(),
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        domain_id: None,
        resolved_user_name: "system-user".to_string(),
        is_system: true,
        resolved_group_bindings: vec![],
        authorizations: vec![Authorization::Project {
            project_id: pid.to_string(),
            project_domain_id: "d1".to_string(),
            roles: roles.clone(),
        }],
        ruleset_version: 1,
        enabled: true,
        created_at: 0,
        last_authenticated_at: 0,
    };

    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_virtual_user()
        .returning(move |_e, id: &str| {
            if id == vir_id {
                Ok(Some(vu.clone()))
            } else {
                Ok(None)
            }
        });

    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: vir_id.to_string(),
        is_system: true,
    };

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity(vir_id))
        .build();

    // No pre-set authorization, target scope is Project (not Unscoped):
    // `is_system` alone must not upgrade this to System scope.
    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state).await;

    let validated = result.unwrap();
    assert!(matches!(
        validated.0.authorization().unwrap().scope,
        ScopeInfo::Project { .. }
    ));
    let eff = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].id, rid);
}

// OSSA-2026-005 / CVE-2026-33551 / OSSA-2026-015 regression matrix:
// drives `ValidatedSecurityContext::new_for_scope()` end-to-end (not
// just `calculate_effective_roles` in isolation) across every scope
// shape a delegated auth (Trust, ApplicationCredential) can legally
// present, and asserts the resulting effective roles never exceed the
// delegation's own restricted role set -- even when the delegating
// principal personally holds broader roles on the target project. See
// `doc/src/contributor/security-model.md` I4 and its reviewer-checklist item "New scope
// shape or redemption path for a delegated auth?".
#[tokio::test]
async fn test_new_for_scope_delegated_roles_never_exceed_delegation_matrix() {
    let trustor = "trustor";
    let appcred_owner = "appcred_owner";
    let pid = "pid";
    let allowed_rid = "reader";
    let escalated_rid = "admin";

    // The delegating principal (trustor, or the app-cred owner) holds
    // BOTH roles on the project; the delegation itself (trust.roles /
    // application_credential.roles) restricts to just `allowed_rid`.
    // A correct implementation must never let the wider assignment
    // leak through.
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .withf(move |_, q: &RoleAssignmentListParameters| q.project_id.as_deref() == Some(pid))
        .returning(move |_e, q: &RoleAssignmentListParameters| {
            let actor = q.user_id.clone().unwrap_or_default();
            Ok(vec![
                assignment_with_role_actor(allowed_rid, &actor),
                assignment_with_role_actor(escalated_rid, &actor),
            ])
        });
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(|_e, _roles| Ok(()));
    let mut trust_mock = MockTrustProvider::default();
    trust_mock
        .expect_validate_trust_delegation_chain()
        .returning(|_e, _trust| Ok(true));
    let mut identity_mock = MockIdentityProvider::default();
    identity_mock.expect_get_user().returning(|_e, id| {
        Ok(Some(
            UserResponseBuilder::default()
                .id(id)
                .domain_id("d1")
                .enabled(true)
                .name(id)
                .build()
                .unwrap(),
        ))
    });
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock)
                .mock_trust(trust_mock)
                .mock_identity(identity_mock),
        ),
    )
    .await;

    // Case 1: Trust presented on its native TrustProject scope, as
    // reconstructed when an already-issued trust token is re-presented
    // (`TokenService::build_authz_info_from_fernet_token` +
    // `SecurityContext::set_authorization`): `authorization` is
    // pre-set to the trust's own scope, which `new_for_scope` then
    // re-confirms is unchanged rather than re-running boundary
    // validation (see this function's doc comment).
    let trust = Trust {
        id: "t1".to_string(),
        trustor_user_id: trustor.to_string(),
        trustee_user_id: "trustee".to_string(),
        impersonation: false,
        project_id: Some(pid.to_string()),
        expires_at: None,
        deleted_at: None,
        extra: None,
        remaining_uses: None,
        redelegated_trust_id: None,
        redelegation_count: None,
        roles: Some(vec![role_ref(allowed_rid, "reader")]),
    };
    let trust_project_scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
        trust: trust.clone(),
        project: make_project(pid),
        project_domain: openstack_keystone_core_types::resource::Domain {
            id: "d1".to_string(),
            description: None,
            enabled: true,
            name: "default".to_string(),
            extra: HashMap::new(),
        },
    }));
    let authz = AuthzInfoBuilder::default()
        .scope(trust_project_scope.clone())
        .roles(Vec::new())
        .build()
        .unwrap();
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Trust {
            trust: trust.clone(),
            token: None,
        })
        .principal(make_user_identity("trustee"))
        .authorization(authz)
        .build();
    let validated = ValidatedSecurityContext::new_for_scope(ctx, trust_project_scope, &state)
        .await
        .unwrap();
    let roles = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(roles.len(), 1, "trust/TrustProject: {roles:?}");
    assert_eq!(roles[0].id, allowed_rid);

    // Case 2: the same trust reconstructed on a bare Project scope --
    // the shape an EC2 credential minted under this trust presents at
    // `/v3/ec2tokens` redemption.
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Trust {
            trust: trust.clone(),
            token: None,
        })
        .principal(make_user_identity("trustee"))
        .build();
    let validated = ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state)
        .await
        .unwrap();
    let roles = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(roles.len(), 1, "trust/Project (EC2 shape): {roles:?}");
    assert_eq!(roles[0].id, allowed_rid);

    // Case 3: a restricted application credential on its (only legal)
    // Project scope.
    let ac = openstack_keystone_core_types::application_credential::ApplicationCredential {
        id: "ac1".to_string(),
        user_id: appcred_owner.to_string(),
        project_id: pid.to_string(),
        name: "cred".to_string(),
        description: None,
        roles: vec![role_ref(allowed_rid, "reader")],
        unrestricted: false,
        expires_at: None,
        access_rules: None,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::ApplicationCredential {
            application_credential: ac,
            token: None,
        })
        .principal(make_user_identity(appcred_owner))
        .build();
    let validated = ValidatedSecurityContext::new_for_scope(ctx, make_project_scope(pid), &state)
        .await
        .unwrap();
    let roles = validated
        .0
        .authorization()
        .unwrap()
        .effective_roles()
        .unwrap();
    assert_eq!(roles.len(), 1, "application_credential/Project: {roles:?}");
    assert_eq!(roles[0].id, allowed_rid);
}

/// Gate D compile-time exhaustiveness anchor (security review V1/V2,
/// issue #981): unlike [`AuthenticationContext::is_delegated`] (a
/// `matches!` over an explicit allow-list, which silently keeps
/// compiling if a variant is added), this match has **no wildcard
/// arm** -- every current variant is named, so adding a new
/// `AuthenticationContext` variant anywhere in the codebase without
/// also classifying it here is a compile error, not a silently-passing
/// test. `test_delegation_scope_kind_matrix_roles_never_exceed_delegation`
/// below is driven from this classification, not from `is_delegated()`.
fn is_delegating_auth_context(ctx: &AuthenticationContext) -> bool {
    match ctx {
        AuthenticationContext::ApplicationCredential { .. } => true,
        AuthenticationContext::Trust { .. } => true,
        AuthenticationContext::Oidc { .. }
        | AuthenticationContext::K8s(_)
        | AuthenticationContext::Password
        | AuthenticationContext::Admin
        | AuthenticationContext::Token(_)
        | AuthenticationContext::WebauthN
        | AuthenticationContext::Mapping(_)
        | AuthenticationContext::Ec2Credential
        | AuthenticationContext::Totp
        | AuthenticationContext::WasmPlugin { .. } => false,
    }
}

/// Gate D's companion anchor for `ScopeInfo`: same no-wildcard
/// requirement. The classification itself is unused by the matrix
/// below (which sweeps every variant unconditionally and only asserts
/// on whichever cells `new_for_scope` happens to accept) -- this
/// function exists purely so a new `ScopeInfo` variant fails to
/// compile here until a human decides how it fits the matrix.
fn classify_scope_kind(scope: &ScopeInfo) -> &'static str {
    match scope {
        ScopeInfo::Domain(_) => "domain",
        ScopeInfo::Project { .. } => "project",
        ScopeInfo::System(_) => "system",
        ScopeInfo::TrustProject(_) => "trust_project",
        ScopeInfo::Unscoped => "unscoped",
    }
}

/// Gate D (security review V1/V2, issue #981): generated matrix over
/// every (delegating `AuthenticationContext` kind) x (`ScopeInfo`
/// variant) cell, driven end-to-end through `new_for_scope()`.
///
/// Unlike the hand-written seed test above, this does not predict
/// allow/deny per cell -- that table already exists and is exhaustively
/// matched in `SecurityContext::validate_scope_boundaries`
/// (`crates/core-types/src/auth.rs`). Instead it asserts the
/// *invariant* mechanically, for every cell: whenever `new_for_scope`
/// accepts a delegated context on some scope, the resulting effective
/// roles never exceed the delegation's own role set, regardless of
/// which scope was requested or whether the delegation is restricted
/// or unrestricted. A cell that returns `Err` is not a failure here --
/// reachability is `validate_scope_boundaries`'s concern, not this
/// test's; this loop only ever asserts on cells that succeed, which is
/// exactly the shape the I4 near-miss (`from_security_context` falling
/// through to `ProjectScopePayload`) would have broken.
#[tokio::test]
async fn test_delegation_scope_kind_matrix_roles_never_exceed_delegation() {
    let pid = "pid";
    let allowed_rid = "reader";
    let escalated_rid = "admin";

    // The delegating principal holds BOTH roles on the project; every
    // delegation kind below restricts to just `allowed_rid`. A
    // regression that lets the wider personal assignment leak through
    // on any cell is exactly what this matrix exists to catch.
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock.expect_list_role_assignments().returning(
        move |_e, q: &RoleAssignmentListParameters| {
            let actor = q.user_id.clone().unwrap_or_default();
            Ok(vec![
                assignment_with_role_actor(allowed_rid, &actor),
                assignment_with_role_actor(escalated_rid, &actor),
            ])
        },
    );
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(|_e, _roles| Ok(()));
    let mut trust_mock = MockTrustProvider::default();
    trust_mock
        .expect_validate_trust_delegation_chain()
        .returning(|_e, _trust| Ok(true));
    let mut identity_mock = MockIdentityProvider::default();
    identity_mock.expect_get_user().returning(|_e, id| {
        Ok(Some(
            UserResponseBuilder::default()
                .id(id)
                .domain_id("d1")
                .enabled(true)
                .name(id)
                .build()
                .unwrap(),
        ))
    });
    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock)
                .mock_trust(trust_mock)
                .mock_identity(identity_mock),
        ),
    )
    .await;

    let trust = Trust {
        id: "t1".to_string(),
        trustor_user_id: "trustor".to_string(),
        trustee_user_id: "trustee".to_string(),
        impersonation: false,
        project_id: Some(pid.to_string()),
        expires_at: None,
        deleted_at: None,
        extra: None,
        remaining_uses: None,
        redelegated_trust_id: None,
        redelegation_count: None,
        roles: Some(vec![role_ref(allowed_rid, "reader")]),
    };
    let ac_restricted =
        openstack_keystone_core_types::application_credential::ApplicationCredential {
            id: "ac1".to_string(),
            user_id: "appcred_owner".to_string(),
            project_id: pid.to_string(),
            name: "cred".to_string(),
            description: None,
            roles: vec![role_ref(allowed_rid, "reader")],
            unrestricted: false,
            expires_at: None,
            access_rules: None,
        };
    let ac_unrestricted =
        openstack_keystone_core_types::application_credential::ApplicationCredential {
            unrestricted: true,
            ..ac_restricted.clone()
        };

    // (label, principal user_id, delegation's own role ids, context builder)
    let delegating_cases: Vec<(
        &str,
        &str,
        Vec<&str>,
        Box<dyn Fn() -> AuthenticationContext>,
    )> = vec![
        (
            "trust",
            "trustee",
            vec![allowed_rid],
            Box::new({
                let t = trust.clone();
                move || AuthenticationContext::Trust {
                    trust: t.clone(),
                    token: None,
                }
            }),
        ),
        (
            "app_cred_restricted",
            "appcred_owner",
            vec![allowed_rid],
            Box::new({
                let ac = ac_restricted.clone();
                move || AuthenticationContext::ApplicationCredential {
                    application_credential: ac.clone(),
                    token: None,
                }
            }),
        ),
        (
            "app_cred_unrestricted",
            "appcred_owner",
            vec![allowed_rid],
            Box::new({
                let ac = ac_unrestricted.clone();
                move || AuthenticationContext::ApplicationCredential {
                    application_credential: ac.clone(),
                    token: None,
                }
            }),
        ),
    ];

    let scope_kinds: Vec<ScopeInfo> = vec![
        make_domain_scope("d1"),
        make_project_scope(pid),
        ScopeInfo::System("all".to_string()),
        make_trust_scope(
            "trustor",
            "trustee",
            pid,
            Some(vec![role_ref(allowed_rid, "reader")]),
        ),
        ScopeInfo::Unscoped,
    ];
    // Exercise every ScopeInfo variant at least once, so a variant
    // added without a row here is visibly under-covered rather than
    // silently skipped (the classifier above still gates it at
    // compile time regardless).
    assert_eq!(scope_kinds.len(), 5);

    for (label, principal_user_id, delegation_roles, ctx_fn) in &delegating_cases {
        assert!(
            is_delegating_auth_context(&ctx_fn()),
            "case {label} must be classified as delegating for this matrix to mean anything"
        );
        for scope in &scope_kinds {
            let scope_label = classify_scope_kind(scope);
            let ctx = SecurityContextTestingBuilder::default()
                .authentication_context(ctx_fn())
                .principal(make_user_identity(*principal_user_id))
                .build();
            let result = ValidatedSecurityContext::new_for_scope(ctx, scope.clone(), &state).await;
            if let Ok(validated) = result
                && let Some(roles) = validated.0.authorization().unwrap().effective_roles()
            {
                for role in roles {
                    assert!(
                        delegation_roles.contains(&role.id.as_str()),
                        "cell ({label}, {scope_label}): effective role {role:?} exceeds \
                             delegation role set {delegation_roles:?}"
                    );
                }
            }
        }
    }
}

// When the trustee's own domain differs from the trustor's domain, the
// trustor's domain enabled-state must be checked, and a disabled
// trustor domain must reject the trust. Catches `delete !` on
// `!trustor_domain_enabled`.
#[tokio::test]
async fn test_new_for_scope_trust_rejected_when_trustor_domain_disabled() {
    use crate::resource::MockResourceProvider;

    let mut trust_mock = MockTrustProvider::default();
    trust_mock
        .expect_validate_trust_delegation_chain()
        .returning(|_e, _trust| Ok(true));
    let mut identity_mock = MockIdentityProvider::default();
    identity_mock.expect_get_user().returning(|_e, id| {
        Ok(Some(
            UserResponseBuilder::default()
                .id(id)
                .domain_id("trustor_domain")
                .enabled(true)
                .name(id)
                .build()
                .unwrap(),
        ))
    });
    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_get_domain_enabled()
        .withf(|_e, domain_id: &str| domain_id == "trustor_domain")
        .returning(|_e, _domain_id| Ok(false));

    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_trust(trust_mock)
                .mock_identity(identity_mock)
                .mock_resource(resource_mock),
        ),
    )
    .await;

    // Trustee's own domain ("d1", per `make_user_identity`) differs
    // from the trustor's domain ("trustor_domain"), so the
    // trustor-domain-enabled branch is exercised.
    let trust = Trust {
        id: "t1".to_string(),
        trustor_user_id: "trustor".to_string(),
        trustee_user_id: "trustee".to_string(),
        impersonation: false,
        project_id: Some("pid".to_string()),
        expires_at: None,
        deleted_at: None,
        extra: None,
        remaining_uses: None,
        redelegated_trust_id: None,
        redelegation_count: None,
        roles: None,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Trust { trust, token: None })
        .principal(make_user_identity("trustee"))
        .build();
    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope("pid"), &state).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::TrustorDomainDisabled)
    ));
}

// Companion positive case: same cross-domain setup, but the trustor's
// domain is enabled, so the trust must succeed.
#[tokio::test]
async fn test_new_for_scope_trust_accepted_when_trustor_domain_enabled() {
    use crate::resource::MockResourceProvider;

    let rid = "reader";
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(move |_e, _q| Ok(vec![assignment_with_role(rid)]));
    let mut role_mock = MockRoleProvider::default();
    role_mock
        .expect_expand_implied_roles()
        .returning(|_e, _roles| Ok(()));
    let mut trust_mock = MockTrustProvider::default();
    trust_mock
        .expect_validate_trust_delegation_chain()
        .returning(|_e, _trust| Ok(true));
    let mut identity_mock = MockIdentityProvider::default();
    identity_mock.expect_get_user().returning(|_e, id| {
        Ok(Some(
            UserResponseBuilder::default()
                .id(id)
                .domain_id("trustor_domain")
                .enabled(true)
                .name(id)
                .build()
                .unwrap(),
        ))
    });
    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_get_domain_enabled()
        .withf(|_e, domain_id: &str| domain_id == "trustor_domain")
        .returning(|_e, _domain_id| Ok(true));

    let state = get_mocked_state(
        None,
        Some(
            Provider::mocked_builder()
                .mock_assignment(assignment_mock)
                .mock_role(role_mock)
                .mock_trust(trust_mock)
                .mock_identity(identity_mock)
                .mock_resource(resource_mock),
        ),
    )
    .await;

    let trust = Trust {
        id: "t1".to_string(),
        trustor_user_id: "trustor".to_string(),
        trustee_user_id: "trustee".to_string(),
        impersonation: false,
        project_id: Some("pid".to_string()),
        expires_at: None,
        deleted_at: None,
        extra: None,
        remaining_uses: None,
        redelegated_trust_id: None,
        redelegation_count: None,
        roles: Some(vec![role_ref(rid, "reader")]),
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Trust { trust, token: None })
        .principal(make_user_identity("trustee"))
        .build();
    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope("pid"), &state).await;
    assert!(result.is_ok());
}

// Companion negative case: a trust may reach a plain Project scope only
// for its OWN bound project -- it must not be usable to reach a
// different project by presenting the EC2-redemption shape.
#[tokio::test]
async fn test_new_for_scope_trust_on_foreign_project_rejected() {
    let state = get_mocked_state(None, None).await;
    let trust = Trust {
        id: "t1".to_string(),
        trustor_user_id: "trustor".to_string(),
        trustee_user_id: "trustee".to_string(),
        impersonation: false,
        project_id: Some("own_pid".to_string()),
        expires_at: None,
        deleted_at: None,
        extra: None,
        remaining_uses: None,
        redelegated_trust_id: None,
        redelegation_count: None,
        roles: None,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Trust { trust, token: None })
        .principal(make_user_identity("trustee"))
        .build();
    let result =
        ValidatedSecurityContext::new_for_scope(ctx, make_project_scope("other_pid"), &state).await;
    assert!(matches!(result, Err(AuthenticationError::ScopeNotAllowed)));
}

/// Builds a `Config` with a single `[auth_plugin.<name>]` section
/// whose only fields under test are `valid_since` (ADR 0025 §4 "Plugin
/// Version Binding").
fn wasm_plugin_config(
    name: &str,
    valid_since: Option<chrono::DateTime<Utc>>,
) -> openstack_keystone_config::Config {
    use config::{Config as RawConfig, File, FileFormat};
    use std::collections::HashMap as StdHashMap;

    #[derive(serde::Deserialize)]
    struct Wrapper {
        auth_plugin: StdHashMap<String, openstack_keystone_config::DynamicPluginConfig>,
    }

    let mut ini = format!(
        "[auth_plugin.{name}]\npath = /dev/null\nsha256 = {}\nmode = full_auth\n",
        "0".repeat(64),
    );
    if let Some(vs) = valid_since {
        ini.push_str(&format!("valid_since = {}\n", vs.to_rfc3339()));
    }
    let c = RawConfig::builder()
        .add_source(File::from_str(&ini, FileFormat::Ini))
        .build()
        .unwrap();
    let wrapper: Wrapper = c.try_deserialize().unwrap();
    openstack_keystone_config::Config {
        auth_plugin: wrapper.auth_plugin,
        ..Default::default()
    }
}

fn wasm_plugin_token(plugin_name: &str, issued_at: chrono::DateTime<Utc>) -> FernetToken {
    FernetToken::Unscoped(openstack_keystone_core_types::token::UnscopedPayload {
        user_id: "uid".to_string(),
        methods: vec![plugin_name.to_string()],
        audit_ids: vec![],
        expires_at: issued_at + chrono::TimeDelta::hours(1),
        issued_at,
        user: None,
    })
}

#[tokio::test]
async fn test_wasm_plugin_stale_token_is_rejected() {
    let valid_since = Utc::now();
    let issued_at = valid_since - chrono::TimeDelta::seconds(60);

    let state = get_mocked_state(Some(wasm_plugin_config("p", Some(valid_since))), None).await;

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::WasmPlugin {
            plugin_name: "p".to_string(),
            claims: HashMap::new(),
            token: None,
        })
        .principal(make_user_identity("uid"))
        .token(wasm_plugin_token("p", issued_at))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::PluginVersionMismatch(ref name)) if name == "p"
    ));
}

#[tokio::test]
async fn test_wasm_plugin_fresh_token_after_cutoff_is_accepted() {
    let valid_since = Utc::now();
    let issued_at = valid_since + chrono::TimeDelta::seconds(60);

    let state = get_mocked_state(Some(wasm_plugin_config("p", Some(valid_since))), None).await;

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::WasmPlugin {
            plugin_name: "p".to_string(),
            claims: HashMap::new(),
            token: None,
        })
        .principal(make_user_identity("uid"))
        .token(wasm_plugin_token("p", issued_at))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;
    assert!(result.is_ok());
}

// Boundary case: `issued_at == valid_since` must be accepted (the check
// is `issued_at < valid_since`, not `<=`). Catches `<` -> `<=`.
#[tokio::test]
async fn test_wasm_plugin_token_issued_exactly_at_cutoff_is_accepted() {
    let valid_since = Utc::now();

    let state = get_mocked_state(Some(wasm_plugin_config("p", Some(valid_since))), None).await;

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::WasmPlugin {
            plugin_name: "p".to_string(),
            claims: HashMap::new(),
            token: None,
        })
        .principal(make_user_identity("uid"))
        .token(wasm_plugin_token("p", valid_since))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_wasm_plugin_fresh_mint_ignores_valid_since() {
    // No `.token(..)` set - mirrors a brand-new mint, where
    // `ctx.token()` is `None` (`SecurityContext::token`'s doc comment).
    // A past `valid_since` must never reject a login that hasn't
    // produced a token yet.
    let valid_since = Utc::now();
    let state = get_mocked_state(Some(wasm_plugin_config("p", Some(valid_since))), None).await;

    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::WasmPlugin {
            plugin_name: "p".to_string(),
            claims: HashMap::new(),
            token: None,
        })
        .principal(make_user_identity("uid"))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_mapping_wasm_plugin_stale_token_is_rejected() {
    use openstack_keystone_core_types::mapping::ruleset::MappingRuleSet;
    use openstack_keystone_core_types::mapping::{DomainResolutionMode, IdentitySource};

    // A `mapping`-mode plugin's version binding is enforced via the same
    // `valid_since` cutoff as `full_auth`, recovering the plugin name
    // from the ruleset's `IdentitySource::WasmPlugin` instead of a
    // token-embedded hash the (unextendable) `FernetToken` can't carry
    // (ADR 0025 §4 "Plugin-version binding for mapping mode").
    let valid_since = Utc::now();
    let issued_at = valid_since - chrono::TimeDelta::seconds(60);

    let ruleset = MappingRuleSet {
        mapping_id: "map-1".to_string(),
        domain_id: Some("d".to_string()),
        source: IdentitySource::WasmPlugin {
            plugin_name: "p".to_string(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![],
        ruleset_version: 1,
    };
    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_ruleset()
        .returning(move |_e, id: &str| {
            if id == "map-1" {
                Ok(Some(ruleset.clone()))
            } else {
                Ok(None)
            }
        });

    let state = get_mocked_state(
        Some(wasm_plugin_config("p", Some(valid_since))),
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: "vu-1".to_string(),
        is_system: false,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity("vu-1"))
        .token(wasm_plugin_token("p", issued_at))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;
    assert!(matches!(
        result,
        Err(AuthenticationError::PluginVersionMismatch(ref name)) if name == "p"
    ));
}

// Boundary case for the mapping-mode plugin-version-binding check:
// `issued_at == valid_since` must be accepted (the check is
// `issued_at < valid_since`, not `<=`). Catches `<` -> `<=`.
#[tokio::test]
async fn test_mapping_wasm_plugin_token_issued_exactly_at_cutoff_is_accepted() {
    use openstack_keystone_core_types::mapping::ruleset::MappingRuleSet;
    use openstack_keystone_core_types::mapping::{DomainResolutionMode, IdentitySource};

    let valid_since = Utc::now();

    let ruleset = MappingRuleSet {
        mapping_id: "map-1".to_string(),
        domain_id: Some("d".to_string()),
        source: IdentitySource::WasmPlugin {
            plugin_name: "p".to_string(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![],
        ruleset_version: 1,
    };
    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_get_ruleset()
        .returning(move |_e, id: &str| {
            if id == "map-1" {
                Ok(Some(ruleset.clone()))
            } else {
                Ok(None)
            }
        });

    let state = get_mocked_state(
        Some(wasm_plugin_config("p", Some(valid_since))),
        Some(Provider::mocked_builder().mock_mapping(mapping_mock)),
    )
    .await;

    let mc = MappingContext {
        mapping_id: "map-1".to_string(),
        matched_rule_name: "rule-1".to_string(),
        virtual_user_id: "vu-1".to_string(),
        is_system: false,
    };
    let ctx = SecurityContextTestingBuilder::default()
        .authentication_context(AuthenticationContext::Mapping(mc))
        .principal(make_user_identity("vu-1"))
        .token(wasm_plugin_token("p", valid_since))
        .build();

    let result = ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_execution_context_has_auth_true_when_authenticated() {
    let state = get_mocked_state(None, None).await;
    let sctx = SecurityContext::test_build()
        .authentication_context(AuthenticationContext::Password)
        .principal(make_user_identity("uid"))
        .build();
    let validated = ValidatedSecurityContext::test_new(sctx);
    let exec_ctx = ExecutionContext::from_auth(&state, &validated);
    assert!(exec_ctx.has_auth());
}

#[tokio::test]
async fn test_execution_context_has_auth_false_when_internal() {
    let state = get_mocked_state(None, None).await;
    let exec_ctx = ExecutionContext::internal(&state);
    assert!(!exec_ctx.has_auth());
}
