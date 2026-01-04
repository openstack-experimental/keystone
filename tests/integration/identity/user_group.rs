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

use openstack_keystone::config::Config;
use openstack_keystone::db::entity::{
    identity_provider as db_identity_provider, prelude::IdentityProvider as DbIdentityProvider,
    project,
};
use openstack_keystone::identity::IdentityApi;
use openstack_keystone::identity::types::*;
use openstack_keystone::keystone::{Service, ServiceState};
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;

use crate::common::{bootstrap, get_isolated_database};

mod add;
mod list;

async fn setup_data(db: &DbConn) -> Result<(), Report> {
    bootstrap(db).await?;
    // Domain/project data
    let _domain_a = project::ActiveModel {
        is_domain: Set(true),
        id: Set("domain_a".into()),
        name: Set("domain_a".into()),
        extra: NotSet,
        description: NotSet,
        enabled: Set(Some(true)),
        domain_id: Set("<<keystone.domain.root>>".into()),
        parent_id: NotSet,
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
    let db = get_isolated_database().await?;
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
