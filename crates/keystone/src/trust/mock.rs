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
//! Trust - internal mocking tools.
use async_trait::async_trait;
#[cfg(test)]
use mockall::mock;

use crate::config::Config;
use crate::plugin_manager::PluginManager;
use crate::trust::{TrustApi, TrustError, types::*};

use crate::keystone::ServiceState;

#[cfg(test)]
mock! {
    pub TrustProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, TrustError>;
    }

    #[async_trait]
    impl TrustApi for TrustProvider {
        async fn get_trust<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<Trust>, TrustError>;

        async fn get_trust_delegation_chain<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<Vec<Trust>>, TrustError>;

        async fn list_trusts(
            &self,
            state: &ServiceState,
            params: &TrustListParameters,
        ) -> Result<Vec<Trust>, TrustError>;

        async fn validate_trust_delegation_chain(
            &self,
            state: &ServiceState,
            trust: &Trust,
        ) -> Result<bool, TrustError>;
    }
}
