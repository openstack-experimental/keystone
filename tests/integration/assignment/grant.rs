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

mod list;

use eyre::Report;
use sea_orm::{Database, DbConn, entity::*};
use std::sync::Arc;

use openstack_keystone::config::Config;
use openstack_keystone::db::entity::{
    assignment, group, prelude::*, project, role, sea_orm_active_enums::Type, user,
    user_group_membership,
};
use openstack_keystone::keystone::Service;
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;

//use super::setup_schema;
use crate::common::{bootstrap, setup_schema};

async fn setup_assignment_data(db: &DbConn) -> Result<(), Report> {
    bootstrap(db).await?;
    // Domain/project data
    Project::insert_many([
        project::ActiveModel {
            is_domain: Set(true),
            id: Set("domain_a".into()),
            name: Set("domain_a".into()),
            extra: NotSet,
            description: NotSet,
            enabled: Set(Some(true)),
            domain_id: Set("<<keystone.domain.root>>".into()),
            parent_id: NotSet,
        },
        project::ActiveModel {
            is_domain: Set(false),
            id: Set("project_a".into()),
            name: Set("project_a".into()),
            extra: NotSet,
            description: NotSet,
            enabled: Set(Some(true)),
            domain_id: Set("domain_a".to_string()),
            parent_id: Set(Some("domain_a".to_string())),
        },
        project::ActiveModel {
            is_domain: Set(false),
            id: Set("project_a_1".into()),
            name: Set("project_a_1".into()),
            extra: NotSet,
            description: NotSet,
            enabled: Set(Some(true)),
            domain_id: Set("domain_a".to_string()),
            parent_id: Set(Some("project_a".to_string())),
        },
    ])
    .exec(db)
    .await?;

    // Roles
    Role::insert_many([
        role::ActiveModel {
            id: Set("role_ga".into()),
            name: Set("role_ga".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".to_string()),
        },
        role::ActiveModel {
            id: Set("role_gb".into()),
            name: Set("role_gb".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".to_string()),
        },
        role::ActiveModel {
            id: Set("role_c".into()),
            name: Set("role_c".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".to_string()),
        },
        role::ActiveModel {
            id: Set("role_gc".into()),
            name: Set("role_gc".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".to_string()),
        },
        role::ActiveModel {
            id: Set("role_d".into()),
            name: Set("role_d".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".to_string()),
        },
        role::ActiveModel {
            id: Set("role_gd".into()),
            name: Set("role_gd".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".to_string()),
        },
    ])
    .exec(db)
    .await?;

    // Group
    let group_a = group::ActiveModel {
        id: Set("group_a".into()),
        name: Set("group_a".into()),
        domain_id: Set("domain_a".to_string()),
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
        domain_id: Set("domain_a".to_string()),
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
        target_id: Set("domain_a".to_string()),
        role_id: Set("role_a".to_string()),
        inherited: Set(false),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::GroupDomain),
        actor_id: Set(group_a.id.clone()),
        target_id: Set("domain_a".to_string()),
        role_id: Set("role_ga".to_string()),
        inherited: Set(false),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::UserDomain),
        actor_id: Set(user_a.id.clone()),
        target_id: Set("domain_a".to_string()),
        role_id: Set("role_b".to_string()),
        inherited: Set(true),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::GroupDomain),
        actor_id: Set(group_a.id.clone()),
        target_id: Set("domain_a".to_string()),
        role_id: Set("role_gb".to_string()),
        inherited: Set(true),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::UserProject),
        actor_id: Set(user_a.id.clone()),
        target_id: Set("project_a".to_string()),
        role_id: Set("role_c".to_string()),
        inherited: Set(false),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::GroupProject),
        actor_id: Set(group_a.id.clone()),
        target_id: Set("project_a".to_string()),
        role_id: Set("role_gc".to_string()),
        inherited: Set(false),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::UserProject),
        actor_id: Set(user_a.id.clone()),
        target_id: Set("project_a".to_string()),
        role_id: Set("role_d".to_string()),
        inherited: Set(true),
    }
    .insert(db)
    .await?;
    assignment::ActiveModel {
        r#type: Set(Type::GroupProject),
        actor_id: Set(group_a.id.clone()),
        target_id: Set("project_a".to_string()),
        role_id: Set("role_gd".to_string()),
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
