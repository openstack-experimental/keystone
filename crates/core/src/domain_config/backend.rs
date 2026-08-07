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

//! # Domain configuration driver interface

use async_trait::async_trait;

use openstack_keystone_core_types::domain_config::*;

use crate::domain_config::DomainConfigProviderError;
use crate::keystone::ServiceState;

/// Domain configuration driver interface.
///
/// Mirrors the granularity of the `/v3/domains/{domain_id}/config` API: every
/// verb exists for the whole configuration, for a single group and for a
/// single option.
///
/// # Sensitive options
///
/// `ldap.password` is sensitive: it can be written but must never be read
/// back. Drivers are expected to keep sensitive options in separate storage
/// (python-keystone uses a second table) and:
///
/// - return them as part of [`DomainConfig`] from [`Self::get_domain_config`],
///   which the identity backend needs in order to bind (see
///   [`DomainConfig::resolve_ldap`]) and which never reaches the wire because
///   [`DomainConfig`] strips them on serialization;
/// - never return them from [`Self::get_domain_config_group`] or
///   [`Self::get_domain_config_option`], which back the readable endpoints.
///
/// The option-scoped methods traffic in [`DomainConfigOption`] rather than a
/// bare [`DomainConfigValue`] for the same reason: a value on its own carries
/// no sensitivity marker, so it renders in full under `Debug` and serializes
/// transparently. Since drivers in this workspace are conventionally annotated
/// with `#[tracing::instrument]`, a bare value would put a bind password into
/// the span fields of every write to `ldap.password`. `DomainConfigOption`
/// redacts its value in `Debug` whenever the option is sensitive.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DomainConfigBackend: Send + Sync {
    /// Replace the whole configuration of a domain.
    ///
    /// Backs `PUT /v3/domains/{domain_id}/config`: options absent from
    /// `config` are removed, sensitive storage included.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain to configure.
    /// - `config`: The configuration to store.
    ///
    /// # Returns
    /// - `Result<DomainConfig, DomainConfigProviderError>` - The stored
    ///   configuration, or an error.
    async fn create_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigCreate,
    ) -> Result<DomainConfig, DomainConfigProviderError>;

    /// Get the whole configuration of a domain.
    ///
    /// The result includes sensitive options, so that the identity backend can
    /// be initialized from it; see the trait level note.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// - `Result<Option<DomainConfig>, DomainConfigProviderError>` - The
    ///   configuration, `None` when the domain has none, or an error.
    async fn get_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<DomainConfig>, DomainConfigProviderError>;

    /// Get a single configuration group of a domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group to read.
    ///
    /// # Returns
    /// - `Result<Option<DomainConfigGroup>, DomainConfigProviderError>` - The
    ///   group without any sensitive option, `None` when the domain has no
    ///   option stored in it, or an error.
    async fn get_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<Option<DomainConfigGroup>, DomainConfigProviderError>;

    /// Get a single configuration option of a domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group holding the option.
    /// - `option`: The option to read.
    ///
    /// # Returns
    /// - `Result<Option<DomainConfigOption>, DomainConfigProviderError>` - The
    ///   stored option, or `None` when it is not stored for the domain or is
    ///   sensitive, or an error.
    async fn get_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError>;

    /// Merge changes into the whole configuration of a domain.
    ///
    /// Backs `PATCH /v3/domains/{domain_id}/config`: options absent from
    /// `config` keep their stored value.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    /// - `config`: The options to change.
    ///
    /// # Returns
    /// - `Result<DomainConfig, DomainConfigProviderError>` - The resulting
    ///   configuration, or an error.
    async fn update_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfig, DomainConfigProviderError>;

    /// Merge changes into a single configuration group of a domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group to change.
    /// - `config`: The options to change; only `group` may be populated.
    ///
    /// # Returns
    /// - `Result<DomainConfigGroup, DomainConfigProviderError>` - The resulting
    ///   group, or an error.
    async fn update_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError>;

    /// Change a single configuration option of a domain.
    ///
    /// The option to write is passed whole rather than as a `(group, option,
    /// value)` triple so that a sensitive value is never held in a type that
    /// renders it in full; see the trait level note.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    /// - `option`: The option to change, carrying its group, name and value.
    ///
    /// # Returns
    /// - `Result<DomainConfigOption, DomainConfigProviderError>` - The stored
    ///   option, or an error.
    async fn update_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        option: DomainConfigOption,
    ) -> Result<DomainConfigOption, DomainConfigProviderError>;

    /// Delete the whole configuration of a domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful, or
    ///   an error.
    async fn delete_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<(), DomainConfigProviderError>;

    /// Delete a single configuration group of a domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group to delete.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful, or
    ///   an error.
    async fn delete_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<(), DomainConfigProviderError>;

    /// Delete a single configuration option of a domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    /// - `group`: The group holding the option.
    /// - `option`: The option to delete.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful, or
    ///   an error.
    async fn delete_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<(), DomainConfigProviderError>;

    /// Try to register a domain for a configuration type.
    ///
    /// A registration is a lock one domain holds over a configuration type, so
    /// that at most one domain drives a given mechanism at a time —
    /// python-keystone claims the `SQL` type for the single domain whose
    /// identity backend may be the SQL one while domain specific drivers are
    /// loaded from the database.
    ///
    /// Drivers are expected to make the claim atomic (python-keystone relies on
    /// the primary key of its `config_register` table) rather than reading the
    /// current holder and then writing: two nodes claiming the same type
    /// concurrently must not both be told they hold it.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain claiming the type.
    /// - `driver_type`: The registration type to claim.
    ///
    /// # Returns
    /// - `Result<bool, DomainConfigProviderError>` - `true` when the domain now
    ///   holds the registration, `false` when somebody already does — which
    ///   includes the domain making the request, matching python-keystone's
    ///   `obtain_registration`.
    async fn obtain_registration<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        driver_type: &'a str,
    ) -> Result<bool, DomainConfigProviderError>;

    /// Read which domain holds the registration of a configuration type.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `driver_type`: The registration type to look up.
    ///
    /// # Returns
    /// - `Result<Option<String>, DomainConfigProviderError>` - The ID of the
    ///   domain holding it, `None` when nobody does (python-keystone's
    ///   `ConfigRegistrationNotFound`), or an error.
    async fn read_registration<'a>(
        &self,
        state: &ServiceState,
        driver_type: &'a str,
    ) -> Result<Option<String>, DomainConfigProviderError>;

    /// Release the registrations a domain holds.
    ///
    /// Releasing what the domain does not hold is not an error, and never takes
    /// a registration away from another domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain releasing them.
    /// - `driver_type`: The single type to release, or `None` for every type
    ///   the domain holds.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful, or
    ///   an error.
    async fn release_registration<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        driver_type: Option<&'a str>,
    ) -> Result<(), DomainConfigProviderError>;

    /// Get the global defaults a domain without configuration falls back to.
    ///
    /// Backs `GET /v3/domains/config/default`. Defaults come from the running
    /// configuration rather than from storage, so the provided implementation
    /// is what every driver wants; it is overridable only for drivers that
    /// resolve defaults differently.
    ///
    /// Every whitelisted option is reported, with a `null` value when nothing
    /// is configured for it, the way python-keystone's `get_config_default`
    /// does. Use [`DomainConfig::default_options`] for the same thing as a flat
    /// list.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    ///
    /// # Returns
    /// - `Result<DomainConfig, DomainConfigProviderError>` - The defaults of
    ///   every group, without any sensitive option, or an error.
    async fn get_default_config(
        &self,
        state: &ServiceState,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        let config = state.config_manager.config.read().await;
        DomainConfig::defaults(&config)
    }

    /// Get the global defaults of a single group.
    ///
    /// Backs `GET /v3/domains/config/{group}/default`.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `group`: The group to read.
    ///
    /// # Returns
    /// - `Result<DomainConfigGroup, DomainConfigProviderError>` - The defaults
    ///   of the group, without any sensitive option, or an error.
    async fn get_default_group(
        &self,
        state: &ServiceState,
        group: DomainConfigGroupName,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError> {
        let config = state.config_manager.config.read().await;
        DomainConfig::default_group(&config, group)
    }

    /// Get the global default of a single option.
    ///
    /// Backs `GET /v3/domains/config/{group}/{option}/default`.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `group`: The group holding the option.
    /// - `option`: The option to read.
    ///
    /// # Returns
    /// - `Result<Option<DomainConfigOption>, DomainConfigProviderError>` - The
    ///   default (a JSON `null` value when nothing is configured for it), or
    ///   [`DomainConfigProviderError::UnsupportedOption`] when the option is
    ///   not readable.
    async fn get_default_option<'a>(
        &self,
        state: &ServiceState,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
        let config = state.config_manager.config.read().await;
        Ok(DomainConfig::default_option(&config, group, option)?
            .map(|value| DomainConfigOption::new(group, option, value)))
    }
}
