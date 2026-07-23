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

use std::collections::HashMap;
use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::project::ProjectCreateBuilder;
use openstack_keystone_api_types::v3::trust::*;
use openstack_keystone_api_types::v3::user::{User, UserCreateBuilder};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::assignment::grant::add_project_grant;
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::identity::user::create_user;
use test_api::resource::project::create_project;
use test_api::role::list_roles;
use test_api::trust::create_trust;

use super::TrustorSession;

async fn new_trustee(tc: &Arc<AsyncOpenStack>) -> Result<AsyncResourceGuard<User>> {
    create_user(
        tc,
        UserCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .enabled(true)
            .build()?,
    )
    .await
}

#[tokio::test]
#[traced_test]
async fn test_create_unscoped_trust() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let trustor = TrustorSession::provision(&tc, "default").await?;
    let trustee = new_trustee(&tc).await?;

    let trust = create_trust(
        &trustor.session,
        TrustCreate {
            id: None,
            trustor_user_id: trustor.user.id.clone(),
            trustee_user_id: trustee.id.clone(),
            project_id: None,
            impersonation: false,
            expires_at: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles: Vec::new(),
            extra: None,
        },
    )
    .await?;

    assert!(!trust.id.is_empty());
    assert_eq!(trust.trustor_user_id, trustor.user.id);
    assert_eq!(trust.trustee_user_id, trustee.id);
    assert!(trust.project_id.is_none());

    trust.delete().await?;
    trustee.delete().await?;
    trustor.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_granted_roles() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let trustor = TrustorSession::provision(&tc, "default").await?;
    let trustee = new_trustee(&tc).await?;

    let project = create_project(
        &tc,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(Uuid::new_v4().simple().to_string())
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&tc)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member_role_id = roles.get("member").expect("member role must exist");
    add_project_grant(&tc, &project.id, &trustor.user.id, member_role_id).await?;

    let trust = create_trust(
        &trustor.session,
        TrustCreate {
            id: None,
            trustor_user_id: trustor.user.id.clone(),
            trustee_user_id: trustee.id.clone(),
            project_id: Some(project.id.clone()),
            impersonation: false,
            expires_at: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles: vec![TrustRoleRef {
                domain_id: None,
                id: member_role_id.clone(),
                name: None,
            }],
            extra: None,
        },
    )
    .await?;

    assert_eq!(trust.project_id.as_deref(), Some(project.id.as_str()));
    assert!(trust.roles.iter().any(|r| &r.id == member_role_id));

    trust.delete().await?;
    project.delete().await?;
    trustee.delete().await?;
    trustor.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_role_not_granted_fails() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let trustor = TrustorSession::provision(&tc, "default").await?;
    let trustee = new_trustee(&tc).await?;

    let project = create_project(
        &tc,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(Uuid::new_v4().simple().to_string())
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&tc)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member_role_id = roles.get("member").expect("member role must exist");
    // No grant to the trustor on `project`.

    let result = create_trust(
        &trustor.session,
        TrustCreate {
            id: None,
            trustor_user_id: trustor.user.id.clone(),
            trustee_user_id: trustee.id.clone(),
            project_id: Some(project.id.clone()),
            impersonation: false,
            expires_at: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles: vec![TrustRoleRef {
                domain_id: None,
                id: member_role_id.clone(),
                name: None,
            }],
            extra: None,
        },
    )
    .await;

    assert!(
        result.is_err(),
        "creating a trust with an ungranted role must fail"
    );

    project.delete().await?;
    trustee.delete().await?;
    trustor.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_project_without_roles_fails() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let trustor = TrustorSession::provision(&tc, "default").await?;
    let trustee = new_trustee(&tc).await?;

    let project = create_project(
        &tc,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(Uuid::new_v4().simple().to_string())
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let result = create_trust(
        &trustor.session,
        TrustCreate {
            id: None,
            trustor_user_id: trustor.user.id.clone(),
            trustee_user_id: trustee.id.clone(),
            project_id: Some(project.id.clone()),
            impersonation: false,
            expires_at: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles: Vec::new(),
            extra: None,
        },
    )
    .await;

    assert!(result.is_err(), "project_id without roles must be rejected");

    project.delete().await?;
    trustee.delete().await?;
    trustor.cleanup().await?;
    Ok(())
}
