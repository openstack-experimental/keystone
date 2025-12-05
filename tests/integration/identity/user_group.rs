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

use eyre::Report;
use sea_orm::{
    ConnectOptions, Database, DatabaseBackend, DbConn, entity::*, query::*, schema::Schema,
    sea_query::*,
};
use std::sync::Arc;

use openstack_keystone::config::Config;
//use openstack_keystone::db::entity::prelude::*;
use openstack_keystone::db::entity::{
    group, identity_provider as db_identity_provider,
    prelude::{
        ExpiringUserGroupMembership as DbExpiringUserGroupMembership, Group as DbGroup,
        IdentityProvider as DbIdentityProvider, Project as DbProject, User as DbUser,
        UserGroupMembership as DbUserGroupMembership,
    },
    project, user, user_group_membership,
};
use openstack_keystone::identity::IdentityApi;
use openstack_keystone::identity::types::*;
use openstack_keystone::keystone::{Service, ServiceState};
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;

mod add;
mod list;

async fn setup_schema(db: &DbConn) -> Result<(), Report> {
    // TODO: with sea-orm 2.0 it can be improved
    //db.get_schema_registry("crate::db::entity::*").sync(db).await?;
    // Setup Schema helper
    let schema = Schema::new(DatabaseBackend::Sqlite);

    // Derive from Entity
    let stmts: Vec<TableCreateStatement> = vec![
        schema.create_table_from_entity(DbGroup),
        schema.create_table_from_entity(DbExpiringUserGroupMembership),
        schema.create_table_from_entity(DbIdentityProvider),
        schema.create_table_from_entity(DbProject),
        schema.create_table_from_entity(DbUser),
        schema.create_table_from_entity(DbUserGroupMembership),
    ];

    // Execute create table statement
    for stmt in stmts.iter() {
        db.execute(db.get_database_backend().build(stmt)).await?;
    }

    Ok(())
}

async fn setup_data(db: &DbConn) -> Result<(), Report> {
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

    // Group
    DbGroup::insert_many([
        group::ActiveModel {
            id: Set("group_a".into()),
            name: Set("group_a".into()),
            domain_id: Set(domain_a.id.clone()),
            extra: NotSet,
            description: NotSet,
        },
        group::ActiveModel {
            id: Set("group_b".into()),
            name: Set("group_b".into()),
            domain_id: Set(domain_a.id.clone()),
            extra: NotSet,
            description: NotSet,
        },
        group::ActiveModel {
            id: Set("group_c".into()),
            name: Set("group_c".into()),
            domain_id: Set(domain_a.id.clone()),
            extra: NotSet,
            description: NotSet,
        },
    ])
    .exec(db)
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
        group_id: Set("group_a".to_string()),
    }
    .insert(db)
    .await?;

    DbIdentityProvider::insert_many([db_identity_provider::ActiveModel {
        id: Set("idp_id".into()),
        enabled: Set(true),
        description: NotSet,
        domain_id: Set("domain_a".to_string()),
        authorization_ttl: NotSet,
    }])
    .exec(db)
    .await?;
    Ok(())
}

async fn get_state() -> Result<Arc<Service>, Report> {
    let opt: ConnectOptions = ConnectOptions::new("sqlite::memory:")
        .sqlx_logging(true)
        .to_owned();
    let db = Database::connect(opt).await?;
    setup_schema(&db).await?;
    setup_data(&db).await?;

    let mut cfg: Config = Config::default();
    cfg.federation.default_authorization_ttl = 20;

    let plugin_manager = PluginManager::default();
    let provider = Provider::new(cfg.clone(), plugin_manager)?;
    Ok(Arc::new(Service::new(
        cfg,
        db,
        provider,
        PolicyFactory::default(),
    )?))
}

async fn list_user_groups<U>(state: &ServiceState, user_id: U) -> Result<Vec<Group>, Report>
where
    U: AsRef<str>,
{
    Ok(state
        .provider
        .get_identity_provider()
        .list_groups_of_user(state, user_id.as_ref())
        .await?
        .into_iter()
        .collect())
}
