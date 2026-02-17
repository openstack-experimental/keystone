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

use std::sync::Arc;

use eyre::Report;

use openstack_keystone::config::Config;
use openstack_keystone::keystone::Service;
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;

use crate::common::get_isolated_database;

mod create;
mod list;

async fn get_state() -> Result<Arc<Service>, Report> {
    let db = get_isolated_database().await?;

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
