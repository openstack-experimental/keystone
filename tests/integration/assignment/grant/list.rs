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
//! Test role assignments.

use eyre::Report;
use sea_orm::{Database, DbConn, entity::*};
use std::collections::BTreeSet;
use std::sync::Arc;

use openstack_keystone::assignment::AssignmentApi;
use openstack_keystone::assignment::types::{
    RoleAssignmentListParameters, RoleAssignmentListParametersBuilder,
};
use openstack_keystone::config::Config;
use openstack_keystone::db::entity::{
    assignment, group, project, role, sea_orm_active_enums::Type, user, user_group_membership,
};
use openstack_keystone::keystone::{Service, ServiceState};
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;

use super::setup_schema;

async fn setup_assignment_data(db: &DbConn) -> Result<(), Report> {
    // Domain/project data
    let root_domain = project::ActiveModel {
        is_domain: Set(true),
        id: Set("<<keystone.domain.root>>".into()),
        name: Set("<<keystone.domain.root>>".into()),
        extra: NotSet,
        description: NotSet,
        enabled: Set(Some(true)),
        domain_id: Set("<<keystone.domain.root>>".into()),
        parent_id: NotSet,
    }
    .insert(db)
    .await?;
    let domain_a = project::ActiveModel {
        is_domain: Set(true),
        id: Set("domain_a".into()),
        name: Set("domain_a".into()),
        extra: NotSet,
        description: NotSet,
        enabled: Set(Some(true)),
        domain_id: Set(root_domain.id.clone()),
        parent_id: NotSet,
    }
    .insert(db)
    .await?;
    let project_a = project::ActiveModel {
        is_domain: Set(false),
        id: Set("project_a".into()),
        name: Set("project_a".into()),
        extra: NotSet,
        description: NotSet,
        enabled: Set(Some(true)),
        domain_id: Set(domain_a.id.clone()),
        parent_id: Set(Some(domain_a.id.clone())),
    }
    .insert(db)
    .await?;
    let _project_a_1 = project::ActiveModel {
        is_domain: Set(false),
        id: Set("project_a_1".into()),
        name: Set("project_a_1".into()),
        extra: NotSet,
        description: NotSet,
        enabled: Set(Some(true)),
        domain_id: Set(domain_a.id.clone()),
        parent_id: Set(Some(project_a.id.clone())),
    }
    .insert(db)
    .await?;

    // Roles
    let role_a = role::ActiveModel {
        id: Set("role_a".into()),
        name: Set("role_a".into()),
        extra: NotSet,
        description: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;
    let role_ga = role::ActiveModel {
        id: Set("role_ga".into()),
        name: Set("role_ga".into()),
        extra: NotSet,
        description: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;
    let role_b = role::ActiveModel {
        id: Set("role_b".into()),
        name: Set("role_b".into()),
        extra: NotSet,
        description: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;
    let role_gb = role::ActiveModel {
        id: Set("role_gb".into()),
        name: Set("role_gb".into()),
        extra: NotSet,
        description: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;
    let role_c = role::ActiveModel {
        id: Set("role_c".into()),
        name: Set("role_c".into()),
        extra: NotSet,
        description: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;
    let role_gc = role::ActiveModel {
        id: Set("role_gc".into()),
        name: Set("role_gc".into()),
        extra: NotSet,
        description: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;
    let role_d = role::ActiveModel {
        id: Set("role_d".into()),
        name: Set("role_d".into()),
        extra: NotSet,
        description: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;
    let role_gd = role::ActiveModel {
        id: Set("role_gd".into()),
        name: Set("role_gd".into()),
        extra: NotSet,
        description: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;

    // Group
    let group_a = group::ActiveModel {
        id: Set("group_a".into()),
        name: Set("group_a".into()),
        domain_id: Set(domain_a.id.clone()),
        extra: NotSet,
        description: NotSet,
    }
    .insert(db)
    .await?;
    // User
    let user_a = user::ActiveModel {
        id: Set("user_a".into()),
        extra: NotSet,
        enabled: Set(Some(true)),
        default_project_id: NotSet,
        last_active_at: NotSet,
        created_at: NotSet,
        domain_id: Set(domain_a.id.clone()),
    }
    .insert(db)
    .await?;
    user_group_membership::ActiveModel {
        user_id: Set(user_a.id.clone()),
        group_id: Set(group_a.id.clone()),
    }
    .insert(db)
    .await?;

    // Assignments
    assignment::ActiveModel {
        r#type: Set(Type::UserDomain),
        actor_id: Set(user_a.id.clone()),
        target_id: Set(domain_a.id.clone()),
        role_id: Set(role_a.id.clone()),
        inherited: Set(false),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::GroupDomain),
        actor_id: Set(group_a.id.clone()),
        target_id: Set(domain_a.id.clone()),
        role_id: Set(role_ga.id.clone()),
        inherited: Set(false),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::UserDomain),
        actor_id: Set(user_a.id.clone()),
        target_id: Set(domain_a.id.clone()),
        role_id: Set(role_b.id.clone()),
        inherited: Set(true),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::GroupDomain),
        actor_id: Set(group_a.id.clone()),
        target_id: Set(domain_a.id.clone()),
        role_id: Set(role_gb.id.clone()),
        inherited: Set(true),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::UserProject),
        actor_id: Set(user_a.id.clone()),
        target_id: Set(project_a.id.clone()),
        role_id: Set(role_c.id.clone()),
        inherited: Set(false),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::GroupProject),
        actor_id: Set(group_a.id.clone()),
        target_id: Set(project_a.id.clone()),
        role_id: Set(role_gc.id.clone()),
        inherited: Set(false),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::UserProject),
        actor_id: Set(user_a.id.clone()),
        target_id: Set(project_a.id.clone()),
        role_id: Set(role_d.id.clone()),
        inherited: Set(true),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::GroupProject),
        actor_id: Set(group_a.id.clone()),
        target_id: Set(project_a.id.clone()),
        role_id: Set(role_gd.id.clone()),
        inherited: Set(true),
    }
    .insert(db)
    .await?;

    Ok(())
}

async fn get_state() -> Result<Arc<Service>, Report> {
    let db = Database::connect("sqlite::memory:").await?;
    setup_schema(&db).await?;
    setup_assignment_data(&db).await?;

    let cfg: Config = Config::default();

    let plugin_manager = PluginManager::default();
    let provider = Provider::new(cfg.clone(), plugin_manager)?;
    Ok(Arc::new(Service::new(
        cfg,
        db,
        provider,
        PolicyFactory::default(),
    )?))
}

async fn list_grants(
    state: &ServiceState,
    params: &RoleAssignmentListParameters,
) -> Result<BTreeSet<String>, Report> {
    Ok(state
        .provider
        .get_assignment_provider()
        .list_role_assignments(state, params)
        .await?
        .into_iter()
        .map(|grant| grant.role_id)
        .collect())
}

#[tokio::test]
async fn test_list_user_domain() -> Result<(), Report> {
    let state = get_state().await?;

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .domain_id("domain_a")
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_a".into()]),
        "user has only role_a on the domain"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .domain_id("domain_a")
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_a".into(), "role_ga".into()]),
        "user has role_a, role_ga on the domain"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .group_id("group_a")
                .domain_id("domain_a")
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_a".into(), "role_ga".into()]),
        "group has role_ga on the domain"
    );
    Ok(())
}

#[tokio::test]
async fn test_list_user_tl_project() -> Result<(), Report> {
    let state = get_state().await?;

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .project_id("project_a")
                .effective(false)
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_b".into(), "role_c".into()]),
        "user has role_b inherited from the domain and direct role_c on the TL project (direct)"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .project_id("project_a")
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from([
            "role_b".into(),
            "role_c".into(),
            "role_gb".into(),
            "role_gc".into()
        ]),
        "user has role_b inherited from the domain on the TL project (effective)"
    );
    Ok(())
}

#[tokio::test]
async fn test_list_user_sub_project() -> Result<(), Report> {
    let state = get_state().await?;

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .project_id("project_a_1")
                .effective(false)
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_b".into(), "role_d".into()]),
        "user has only inherited roles on the subproject (effective)"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .project_id("project_a_1")
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from([
            "role_b".into(),
            "role_d".into(),
            "role_gb".into(),
            "role_gd".into()
        ]),
        "user has only inherited roles and groups expanded on the subproject (effective)"
    );
    Ok(())
}
