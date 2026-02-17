// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use mockall::mock;
use std::collections::{BTreeMap, BTreeSet};

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use crate::role::{RoleApi, RoleProviderError, types::*};

mock! {
    pub RoleProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, RoleProviderError>;
    }

    #[async_trait]
    impl RoleApi for RoleProvider {
        async fn create_role(
            &self,
            state: &ServiceState,
            params: RoleCreate,
        ) -> Result<Role, RoleProviderError>;

        async fn get_role<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<Role>, RoleProviderError>;

        async fn expand_implied_roles(
            &self,
            state: &ServiceState,
            roles: &mut Vec<Role>,
        ) -> Result<(), RoleProviderError>;

        async fn list_imply_rules(
            &self,
            state: &ServiceState,
            resolve: bool
        ) -> Result<BTreeMap<String, BTreeSet<String>>, RoleProviderError>;

        async fn list_roles(
            &self,
            state: &ServiceState,
            params: &RoleListParameters,
        ) -> Result<Vec<Role>, RoleProviderError>;
    }
}
