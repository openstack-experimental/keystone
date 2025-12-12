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
use uuid::Uuid;

use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone::application_credential::types;
use openstack_keystone::assignment::types as as_types;
use openstack_keystone::config::Config;
use openstack_keystone::db::entity::prelude::*;
use openstack_keystone::db::entity::{project, role, user};
use openstack_keystone::keystone::Service;
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;

mod create;
mod get;
mod list;

async fn setup_schema(db: &DbConn) -> Result<(), Report> {
    // TODO: with sea-orm 2.0 it can be improved
    //db.get_schema_registry("crate::db::entity::*").sync(db).await?;
    // Setup Schema helper
    let schema = Schema::new(DatabaseBackend::Sqlite);

    // Derive from Entity
    let stmts: Vec<TableCreateStatement> = vec![
        schema.create_table_from_entity(AccessRule),
        schema.create_table_from_entity(ApplicationCredential),
        schema.create_table_from_entity(ApplicationCredentialRole),
        schema.create_table_from_entity(ApplicationCredentialAccessRule),
        schema.create_table_from_entity(Assignment),
        schema.create_table_from_entity(ImpliedRole),
        schema.create_table_from_entity(Project),
        schema.create_table_from_entity(Role),
        schema.create_table_from_entity(User),
    ];

    // Execute create table statement
    for stmt in stmts.iter() {
        db.execute(db.get_database_backend().build(stmt)).await?;
    }

    Ok(())
}

async fn setup_data(db: &DbConn) -> Result<(), Report> {
    // Domain/project data
    Project::insert_many([
        project::ActiveModel {
            is_domain: Set(true),
            id: Set("<<keystone.domain.root>>".into()),
            name: Set("<<keystone.domain.root>>".into()),
            extra: NotSet,
            description: NotSet,
            enabled: Set(Some(true)),
            domain_id: Set("<<keystone.domain.root>>".into()),
            parent_id: NotSet,
        },
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
            domain_id: Set("domain_a".into()),
            parent_id: Set(Some("domain_a".into())),
        },
    ])
    .exec(db)
    .await?;

    // User
    user::ActiveModel {
        id: Set("user_a".into()),
        extra: NotSet,
        enabled: Set(Some(true)),
        default_project_id: NotSet,
        last_active_at: NotSet,
        created_at: NotSet,
        domain_id: Set("domain_a".into()),
    }
    .insert(db)
    .await?;

    // Roles
    Role::insert_many([
        role::ActiveModel {
            id: Set("role_a".into()),
            name: Set("role_a".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".into()),
        },
        role::ActiveModel {
            id: Set("role_b".into()),
            name: Set("role_b".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".into()),
        },
    ])
    .exec(db)
    .await?;

    Ok(())
}

async fn get_state() -> Result<Arc<Service>, Report> {
    let opt: ConnectOptions = ConnectOptions::new("sqlite::memory:")
        .sqlx_logging(false)
        .to_owned();
    let db = Database::connect(opt).await?;
    setup_schema(&db).await?;
    setup_data(&db).await?;

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

async fn create_ac<S>(
    state: &Arc<Service>,
    name: Option<S>,
) -> Result<types::ApplicationCredentialCreateResponse, Report>
where
    S: AsRef<str>,
{
    Ok(state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            state,
            types::ApplicationCredentialCreate {
                access_rules: Some(vec![types::AccessRuleCreate {
                    id: None,
                    path: Some("path1".into()),
                    method: Some("method".into()),
                    service: Some("service".into()),
                }]),
                description: Some("description".into()),
                name: name
                    .map(|v| v.as_ref().to_string())
                    .unwrap_or(Uuid::new_v4().to_string()),
                project_id: "project_a".into(),
                roles: vec![
                    as_types::Role {
                        id: "role_a".into(),
                        ..Default::default()
                    },
                    as_types::Role {
                        id: "role_b".into(),
                        ..Default::default()
                    },
                ],
                user_id: "user_a".into(),
                ..Default::default()
            },
        )
        .await?)
}
