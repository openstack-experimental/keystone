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

//! # Trust provider interface
use async_trait::async_trait;

use openstack_keystone_core_types::trust::*;

use crate::keystone::ServiceState;
use crate::trust::TrustProviderError;

/// Trust extension provider interface.
#[async_trait]
pub trait TrustApi: Send + Sync {
    /// Get trust by ID.
    ///
    /// * `state` - The current service state.
    /// * `id` - The ID of the trust to retrieve.
    ///
    /// A `Result` containing an `Option` with the `Trust` if found, or an
    /// `Error`.
    async fn get_trust<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Trust>, TrustProviderError>;

    /// Resolve trust chain by the trust ID.
    ///
    /// * `state` - The current service state.
    /// * `id` - The ID of the trust to resolve the chain for.
    ///
    /// A `Result` containing an `Option` with the `Vec<Trust>` if found, or an
    /// `Error`.
    async fn get_trust_delegation_chain<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Vec<Trust>>, TrustProviderError>;

    /// List trusts.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The parameters for listing trusts.
    ///
    /// # Returns
    /// - `Result<Vec<Trust>, TrustProviderError>` - A list of trusts or an
    ///   error.
    async fn list_trusts(
        &self,
        state: &ServiceState,
        params: &TrustListParameters,
    ) -> Result<Vec<Trust>, TrustProviderError>;

    /// Validate trust delegation chain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `trust`: The trust to validate.
    ///
    /// # Returns
    /// - `Result<bool, TrustProviderError>` - Ok(true) if the chain is valid,
    ///   or an error.
    async fn validate_trust_delegation_chain(
        &self,
        state: &ServiceState,
        trust: &Trust,
    ) -> Result<bool, TrustProviderError>;
}
