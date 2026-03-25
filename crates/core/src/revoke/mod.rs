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
//! # Token revocation provider.
//!
//! Token revocation may be implemented in different ways, but in most cases
//! would be represented by the presence of the revocation or the invalidation
//! record matching the certain token parameters.
//!
//! Default backend is the [`sql`](crate::revoke::backend::sql) and uses the
//! database [table](crate::db::entity::revocation_event::Model) for storing the
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
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;
//pub mod types;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::revoke::*;
use openstack_keystone_core_types::token::Token;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::revoke::service::RevokeService;

pub use error::RevokeProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockRevokeProvider;
pub use provider_api::RevokeApi;

/// Revoke provider.
pub enum RevokeProvider {
    Service(RevokeService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockRevokeProvider),
}

impl RevokeProvider {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, RevokeProviderError> {
        Ok(Self::Service(RevokeService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl RevokeApi for RevokeProvider {
    /// Create revocation event.
    async fn create_revocation_event(
        &self,
        state: &ServiceState,
        event: RevocationEventCreate,
    ) -> Result<RevocationEvent, RevokeProviderError> {
        match self {
            Self::Service(provider) => provider.create_revocation_event(state, event).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_revocation_event(state, event).await,
        }
    }

    /// Check whether the token has been revoked or not.
    ///
    /// Checks revocation events matching the token parameters and return
    /// `false` if their count is more than `0`.
    async fn is_token_revoked(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<bool, RevokeProviderError> {
        match self {
            Self::Service(provider) => provider.is_token_revoked(state, token).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.is_token_revoked(state, token).await,
        }
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
        match self {
            Self::Service(provider) => provider.revoke_token(state, token).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.revoke_token(state, token).await,
        }
    }
}
