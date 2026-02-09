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
//

use eyre::Report;
use sea_orm::{DbConn, entity::*};
use std::sync::Arc;
use tempfile::TempDir;

mod application_credential;
mod trust;

use openstack_keystone::assignment::{AssignmentApi, types::AssignmentCreate};
use openstack_keystone::config::Config;
use openstack_keystone::db::entity::prelude::Project;
use openstack_keystone::db::entity::project;
use openstack_keystone::identity::{IdentityApi, types::*};
use openstack_keystone::keystone::Service;
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;

use crate::common::{bootstrap, get_isolated_database};

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

async fn get_state() -> Result<(Arc<Service>, TempDir), Report> {
    let db = get_isolated_database().await?;
    setup_data(&db).await?;

    let tmp_fernet_repo = TempDir::new()?;

    let mut cfg: Config = Config::default();
    cfg.auth.methods = vec!["application_credential".into(), "password".into()];
    cfg.fernet_tokens.key_repository = tmp_fernet_repo.path().to_path_buf();
    let fernet_utils = openstack_keystone::token::backend::fernet::utils::FernetUtils {
        key_repository: cfg.fernet_tokens.key_repository.clone(),
        max_active_keys: cfg.fernet_tokens.max_active_keys,
    };
    fernet_utils.initialize_key_repository()?;

    let plugin_manager = PluginManager::default();
    let provider = Provider::new(cfg.clone(), plugin_manager)?;

    let state = Arc::new(Service::new(cfg, db, provider, PolicyFactory::default())?);

    Ok((state, tmp_fernet_repo))
}

async fn create_user<U: Into<String>>(
    state: &Arc<Service>,
    user_id: Option<U>,
) -> Result<UserResponse, Report> {
    let uid: String = user_id.map(Into::into).unwrap_or("user_id".to_string());
    Ok(state
        .provider
        .get_identity_provider()
        .create_user(
            state,
            UserCreateBuilder::default()
                .id(&uid)
                .name(&uid)
                .domain_id("domain_a")
                .enabled(true)
                .password("foobar")
                .build()?,
        )
        .await?)
}

async fn grant_role_to_user_on_project<U: Into<String>, P: Into<String>, R: Into<String>>(
    state: &Arc<Service>,
    user: U,
    project: P,
    role: R,
) -> Result<(), Report> {
    state
        .provider
        .get_assignment_provider()
        .create_grant(
            state,
            AssignmentCreate::user_project(user, project, role, false),
        )
        .await?;
    Ok(())
}
