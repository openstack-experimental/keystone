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

//! # Domain configuration provider API
//!
//! The subset of [`DomainConfigBackend`](crate::domain_config::DomainConfigBackend)
//! that backs the `/v3/domains/{domain_id}/config` REST endpoints: every verb
//! at the three granularities (whole configuration, single group, single
//! option), plus the read-only defaults. The registration lock methods of the
//! backend are intentionally excluded here -- they only matter once the stored
//! configuration drives identity-driver selection (issue #960).

use async_trait::async_trait;

use openstack_keystone_core_types::domain_config::*;

use crate::domain_config::DomainConfigProviderError;
use crate::keystone::ServiceState;

/// Domain configuration provider API.
///
/// Signatures mirror the backend trait one-for-one so the service layer can
/// delegate straight through. See the backend trait for the sensitive-option
/// contract: `ldap.password` may be written but is never returned by the
/// group- or option-scoped getters.
#[async_trait]
pub trait DomainConfigApi: Send + Sync {
    /// Replace the whole configuration of a domain
    /// (`PUT /v3/domains/{domain_id}/config`).
    async fn create_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigCreate,
    ) -> Result<DomainConfig, DomainConfigProviderError>;

    /// Get the whole configuration of a domain
    /// (`GET /v3/domains/{domain_id}/config`).
    async fn get_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<DomainConfig>, DomainConfigProviderError>;

    /// Get a single configuration group of a domain
    /// (`GET /v3/domains/{domain_id}/config/{group}`).
    async fn get_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<Option<DomainConfigGroup>, DomainConfigProviderError>;

    /// Get a single configuration option of a domain
    /// (`GET /v3/domains/{domain_id}/config/{group}/{option}`).
    async fn get_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError>;

    /// Merge changes into the whole configuration of a domain
    /// (`PATCH /v3/domains/{domain_id}/config`).
    async fn update_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfig, DomainConfigProviderError>;

    /// Merge changes into a single configuration group of a domain
    /// (`PATCH /v3/domains/{domain_id}/config/{group}`).
    async fn update_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError>;

    /// Change a single configuration option of a domain
    /// (`PATCH /v3/domains/{domain_id}/config/{group}/{option}`).
    async fn update_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        option: DomainConfigOption,
    ) -> Result<DomainConfigOption, DomainConfigProviderError>;

    /// Delete the whole configuration of a domain
    /// (`DELETE /v3/domains/{domain_id}/config`).
    async fn delete_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<(), DomainConfigProviderError>;

    /// Delete a single configuration group of a domain
    /// (`DELETE /v3/domains/{domain_id}/config/{group}`).
    async fn delete_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<(), DomainConfigProviderError>;

    /// Delete a single configuration option of a domain
    /// (`DELETE /v3/domains/{domain_id}/config/{group}/{option}`).
    async fn delete_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<(), DomainConfigProviderError>;

    /// Get the global defaults every domain without configuration falls back
    /// to (`GET /v3/domains/config/default`).
    async fn get_default_config(
        &self,
        state: &ServiceState,
    ) -> Result<DomainConfig, DomainConfigProviderError>;

    /// Get the global defaults of a single group
    /// (`GET /v3/domains/config/{group}/default`).
    async fn get_default_group(
        &self,
        state: &ServiceState,
        group: DomainConfigGroupName,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError>;

    /// Get the global default of a single option
    /// (`GET /v3/domains/config/{group}/{option}/default`).
    async fn get_default_option<'a>(
        &self,
        state: &ServiceState,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError>;
}
