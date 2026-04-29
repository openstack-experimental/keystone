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
//! Token revocation: Backends.
//! Revocation provider Backend trait.
use async_trait::async_trait;

use openstack_keystone_core_types::revoke::*;
use openstack_keystone_core_types::token::Token;

use crate::keystone::ServiceState;
use crate::revoke::RevokeProviderError;

//pub mod error;

/// RevokeBackend trait.
///
/// Backend driver interface expected by the revocation provider.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait RevokeBackend: Send + Sync {
    /// Create revocation event.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `event` - The revocation event to create.
    async fn create_revocation_event(
        &self,
        state: &ServiceState,
        event: RevocationEventCreate,
    ) -> Result<RevocationEvent, RevokeProviderError>;

    /// Check token revocation.
    ///
    /// Check whether there are existing revocation records that invalidate the
    /// token.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `token` - The token to check.
    async fn is_token_revoked(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<bool, RevokeProviderError>;

    /// Revoke the token.
    ///
    /// Mark the token as revoked to prohibit from being used even while not
    /// expired.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `token` - The token to revoke.
    async fn revoke_token(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<(), RevokeProviderError>;
}
