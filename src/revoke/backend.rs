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
use dyn_clone::DynClone;

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::revoke::RevokeProviderError;
use crate::token::types::Token;

pub mod error;
pub mod sql;

#[async_trait]
/// RevokeBackend trait.
///
/// Backend driver interface expected by the revocation provider.
pub trait RevokeBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// Check token revocation.
    ///
    /// Check whether there are existing revocation records that invalidate the
    /// token.
    async fn is_token_revoked(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<bool, RevokeProviderError>;

    /// Revoke the token.
    ///
    /// Mark the token as revoked to prohibit from being used even while not
    /// expired.
    async fn revoke_token(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<(), RevokeProviderError>;
}

dyn_clone::clone_trait_object!(RevokeBackend);
