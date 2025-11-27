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
//! Token revocation provider.
//!
//! Token revocation may be implemented in different ways, but in most cases
//! would be represented by the presence of the revocation or the invalidation
//! record matching the certain token parameters.
//!
//! Default backend is the [crate::revoke::backend::sql] and uses the database
//! table [crate::db::entity::revocation_event::Model] for storing the
//! revocation events. They have their own expiration.
//!
//! Tokens are not invalidated by saving the exact value, but rather by saving
//! certain attributes of the token.
//!
//! Following attributes are used for matching of the regular fernet token:
//!
//!   - `audit_id`
//!   - `domain_id`
//!   - `expires_at`
//!   - `project_id`
//!   - `user_id`
//!
//! Additionally the `token.issued_at` is compared to be lower than the
//! `issued_before` field of the revocation record.

use async_trait::async_trait;

pub mod backend;
pub mod error;
#[cfg(test)]
mod mock;
pub(crate) mod types;

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use crate::revoke::backend::{RevokeBackend, sql::SqlBackend};
use crate::revoke::error::RevokeProviderError;
use crate::token::types::Token;

#[cfg(test)]
pub use mock::MockRevokeProvider;
pub use types::*;

/// Revoke provider.
#[derive(Clone, Debug)]
pub struct RevokeProvider {
    /// Backend driver.
    backend_driver: Box<dyn RevokeBackend>,
}

impl RevokeProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, RevokeProviderError> {
        let mut backend_driver =
            if let Some(driver) = plugin_manager.get_revoke_backend(config.revoke.driver.clone()) {
                driver.clone()
            } else {
                match config.revoke.driver.as_str() {
                    "sql" => Box::new(SqlBackend::default()),
                    _ => {
                        return Err(RevokeProviderError::UnsupportedDriver(
                            config.revoke.driver.clone(),
                        ));
                    }
                }
            };
        backend_driver.set_config(config.clone());
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl RevokeApi for RevokeProvider {
    /// Check whether the token has been revoked or not.
    ///
    /// Checks revocation events matching the token parameters and return
    /// `false` if their count is more than `0`.
    #[tracing::instrument(level = "info", skip(self, state, token))]
    async fn is_token_revoked(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<bool, RevokeProviderError> {
        tracing::info!("Checking for the revocation events");
        self.backend_driver.is_token_revoked(state, token).await
    }

    /// Revoke the token.
    ///
    /// Mark the token as revoked to prohibit from being used even while not
    /// expired.
    async fn revoke_token(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<(), RevokeProviderError> {
        self.backend_driver.revoke_token(state, token).await
    }
}
