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
//! Token revocation - internal mocking tools.
use async_trait::async_trait;
#[cfg(test)]
use mockall::mock;

use crate::config::Config;
use crate::plugin_manager::PluginManager;
use crate::revoke::RevokeApi;
use crate::revoke::error::RevokeProviderError;
use crate::token::types::Token;

use crate::keystone::ServiceState;

#[cfg(test)]
mock! {
    pub RevokeProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, RevokeProviderError>;
    }

    #[async_trait]
    impl RevokeApi for RevokeProvider {
        async fn is_token_revoked(
            &self,
            state: &ServiceState,
            token: &Token,
        ) -> Result<bool, RevokeProviderError>;

        async fn revoke_token(
            &self,
            state: &ServiceState,
            token: &Token,
        ) -> Result<(), RevokeProviderError>;
    }

    impl Clone for RevokeProvider {
        fn clone(&self) -> Self;
    }
}
