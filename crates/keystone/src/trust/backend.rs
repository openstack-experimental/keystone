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
//! Trust provider Backend trait.
use async_trait::async_trait;

use crate::keystone::ServiceState;
use crate::trust::{TrustProviderError, types::*};

pub mod sql;

pub use sql::SqlBackend;

/// TrustBackend trait.
///
/// Backend driver interface expected by the trust provider.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TrustBackend: Send + Sync {
    /// Get trust by ID.
    async fn get_trust<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Trust>, TrustProviderError>;

    /// Resolve trust chain by the trust ID.
    async fn get_trust_delegation_chain<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Vec<Trust>>, TrustProviderError>;

    /// List trusts.
    async fn list_trusts(
        &self,
        state: &ServiceState,
        params: &TrustListParameters,
    ) -> Result<Vec<Trust>, TrustProviderError>;
}
