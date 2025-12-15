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
//! # Federation provider
//!
//! Federation provider implements the functionality necessary for the user
//! fedefation.
use async_trait::async_trait;

use crate::federation::error::FederationProviderError;
use crate::federation::types::*;
use crate::keystone::ServiceState;

/// Federation provider interface.
#[async_trait]
pub trait FederationApi: Send + Sync + Clone {
    /// Cleanup expired resources
    async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError>;

    async fn create_identity_provider(
        &self,
        state: &ServiceState,
        idp: IdentityProviderCreate,
    ) -> Result<IdentityProvider, FederationProviderError>;

    async fn create_auth_state(
        &self,
        state: &ServiceState,
        state: AuthState,
    ) -> Result<AuthState, FederationProviderError>;

    async fn create_mapping(
        &self,
        state: &ServiceState,
        mapping: Mapping,
    ) -> Result<Mapping, FederationProviderError>;

    async fn delete_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    async fn delete_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    async fn delete_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError>;

    async fn get_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError>;

    async fn get_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError>;

    async fn get_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Mapping>, FederationProviderError>;

    async fn list_identity_providers(
        &self,
        state: &ServiceState,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError>;

    async fn list_mappings(
        &self,
        state: &ServiceState,
        params: &MappingListParameters,
    ) -> Result<Vec<Mapping>, FederationProviderError>;

    async fn update_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError>;

    async fn update_mapping<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        mapping: MappingUpdate,
    ) -> Result<Mapping, FederationProviderError>;
}
