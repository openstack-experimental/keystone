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
use sea_orm::{DbConn, entity::*};
use std::sync::Arc;
use uuid::Uuid;

use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone_config::Config;
use openstack_keystone_core::keystone::Service;
use openstack_keystone_core::policy::MockPolicy;
use openstack_keystone_core::provider::Provider;
use openstack_keystone_core_types::application_credential as types;
use openstack_keystone_core_types::role as role_types;
use openstack_keystone_resource_sql::entity::{prelude::Project, project};

mod create;
mod get;
mod list;

use crate::common::{bootstrap, create_role, create_user, get_isolated_database};

async fn setup_data(db: &DbConn) -> Result<(), Report> {
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
            domain_id: Set("domain_a".into()),
            parent_id: Set(Some("domain_a".into())),
        },
    ])
    .exec(db)
    .await?;

    Ok(())
}

async fn get_state() -> Result<Arc<Service>, Report> {
    let db = get_isolated_database().await?;
    setup_data(&db).await?;

    let cfg: Config = Config::default();

    let plugin_manager = PluginManager::default();
    let provider = Provider::new(cfg.clone(), &plugin_manager)?;
    let state = Arc::new(Service::new(
        cfg,
        db,
        provider,
        Arc::new(MockPolicy::default()),
    )?);

    create_role(&state, "role_a").await?;
    create_role(&state, "role_b").await?;
    create_user(&state, Some("user_a")).await?;
    Ok(state)
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
                    role_types::RoleRef {
                        id: "role_a".into(),
                        name: Some("role_a".into()),
                        domain_id: None,
                    },
                    role_types::RoleRef {
                        id: "role_b".into(),
                        name: Some("role_b".into()),
                        domain_id: None,
                    },
                ],
                user_id: "user_a".into(),
                ..Default::default()
            },
        )
        .await?)
}
