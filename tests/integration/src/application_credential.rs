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
use openstack_keystone::application_credential::types;
use openstack_keystone::config::Config;
use openstack_keystone::db::entity::prelude::*;
use openstack_keystone::db::entity::project;
use openstack_keystone::keystone::Service;
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;
use openstack_keystone::role::types as role_types;

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
    let provider = Provider::new(cfg.clone(), plugin_manager)?;
    let state = Arc::new(Service::new(cfg, db, provider, PolicyFactory::default())?);

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
                    role_types::Role {
                        id: "role_a".into(),
                        name: "role_a".into(),
                        ..Default::default()
                    },
                    role_types::Role {
                        id: "role_b".into(),
                        name: "role_b".into(),
                        ..Default::default()
                    },
                ],
                user_id: "user_a".into(),
                ..Default::default()
            },
        )
        .await?)
}
