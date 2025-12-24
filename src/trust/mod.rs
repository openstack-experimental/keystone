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
//! # Trust provider.
//!
//! Trusts
//!
//! A trust represents a user’s (the trustor) authorization to delegate roles to
//! another user (the trustee), and optionally allow the trustee to impersonate
//! the trustor. After the trustor has created a trust, the trustee can specify
//! the trust’s id attribute as part of an authentication request to then create
//! a token representing the delegated authority of the trustor.
//!
//! The trust contains constraints on the delegated attributes. A token created
//! based on a trust will convey a subset of the trustor’s roles on the
//! specified project. Optionally, the trust may only be valid for a specified
//! time period, as defined by expires_at. If no expires_at is specified, then
//! the trust is valid until it is explicitly revoked.
//!
//! The impersonation flag allows the trustor to optionally delegate
//! impersonation abilities to the trustee. To services validating the token,
//! the trustee will appear as the trustor, although the token will also contain
//! the impersonation flag to indicate that this behavior is in effect.
//!
//! A project_id may not be specified without at least one role, and vice versa.
//! In other words, there is no way of implicitly delegating all roles to a
//! trustee, in order to prevent users accidentally creating trust that are much
//! more broad in scope than intended. A trust without a project_id or any
//! delegated roles is unscoped, and therefore does not represent authorization
//! on a specific resource.
//!
//! Trusts are immutable. If the trustee or trustor wishes to modify the
//! attributes of the trust, they should create a new trust and delete the old
//! trust. If a trust is deleted, any tokens generated based on the trust are
//! immediately revoked.
//!
//! If the trustor loses access to any delegated attributes, the trust becomes
//! immediately invalid and any tokens generated based on the trust are
//! immediately revoked.
//!
//! Trusts can also be chained, meaning, a trust can be created by using a trust
//! scoped token.

use async_trait::async_trait;
//
pub mod backend;
pub mod error;
#[cfg(test)]
mod mock;
pub mod types;
//
use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use backend::{SqlBackend, TrustBackend};

pub use error::TrustError;
#[cfg(test)]
pub use mock::MockTrustProvider;
pub use types::*;

//
/// Revoke provider.
#[derive(Clone, Debug)]
pub struct TrustProvider {
    /// Backend driver.
    backend_driver: Box<dyn TrustBackend>,
}
impl TrustProvider {
    pub fn new(config: &Config, plugin_manager: &PluginManager) -> Result<Self, TrustError> {
        let mut backend_driver =
            if let Some(driver) = plugin_manager.get_trust_backend(config.trust.driver.clone()) {
                driver.clone()
            } else {
                match config.trust.driver.as_str() {
                    "sql" => Box::new(SqlBackend::default()),
                    _ => {
                        return Err(TrustError::UnsupportedDriver(config.trust.driver.clone()));
                    }
                }
            };
        backend_driver.set_config(config.clone());
        Ok(Self { backend_driver })
    }
}
//
#[async_trait]
impl TrustApi for TrustProvider {
    /// Get trust by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_trust<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Trust>, TrustError> {
        self.backend_driver.get_trust(state, id).await
    }

    /// List trusts.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_trusts(
        &self,
        state: &ServiceState,
        params: &TrustListParameters,
    ) -> Result<Vec<Trust>, TrustError> {
        self.backend_driver.list_trusts(state, params).await
    }
}
