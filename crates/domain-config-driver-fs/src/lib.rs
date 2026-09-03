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

//! # OpenStack Keystone filesystem driver for the domain configuration provider
//!
//! Reads per-domain overrides of the identity backend configuration from
//! files, the way python-keystone reads them when
//! `domain_configurations_from_database` is off: one INI file per domain,
//! named `keystone.{domain_name}.conf`, under the directory named by
//! `[identity] domain_config_dir` (default `/etc/keystone/domains`).
//!
//! An INI section is a configuration group and a key is an option. Only the
//! `identity` and `ldap` groups are honoured; any other section, and any
//! option outside the group's whitelist, is dropped with a warning, matching
//! what the API driver does with an unsupported option. Values are kept as the
//! strings the file spells them with; [`DomainConfig`] and its consumers
//! coerce them to the option's real type when they are resolved.
//!
//! The whole directory is read once, when the driver is built at startup, and
//! held in memory. A change to a file therefore takes effect only after a
//! restart. A missing directory is normal and yields an empty driver; a
//! directory that cannot be read, or a file that cannot be parsed, fails
//! startup.
//!
//! The driver is **read-only**. Every create, update, delete and registration
//! method returns [`DomainConfigProviderError::Readonly`]; writes go to the
//! SQL driver. When phase 3 layers the file configuration underneath the
//! database configuration, a compositing backend will hold both — this driver
//! only has to answer reads correctly on its own.

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::domain_config::backend::DomainConfigBackend;
use openstack_keystone_core::domain_config::error::DomainConfigProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core_types::domain_config::*;

mod get;
mod store;

/// Build the error every write path of this driver returns.
fn readonly(operation: &str) -> DomainConfigProviderError {
    DomainConfigProviderError::Readonly(format!(
        "the filesystem domain config driver cannot {operation}"
    ))
}

/// The filesystem domain configuration driver.
pub struct FsBackend {
    /// The parsed contents of every `keystone.{domain_name}.conf` file found
    /// in `domain_config_dir`, keyed by domain name.
    store: Arc<store::DomainConfigStore>,
}

impl FsBackend {
    /// Load the driver from the directory named by `[identity] domain_config_dir`.
    ///
    /// # Parameters
    /// - `config`: The service configuration.
    ///
    /// # Returns
    /// The driver holding every domain config file that parsed, or an error
    /// when the directory exists but cannot be read or holds a file that
    /// cannot be parsed.
    pub fn new(config: &Config) -> Result<Self, DomainConfigProviderError> {
        let store = store::DomainConfigStore::load(&config.identity.domain_config_dir)?;
        Ok(Self {
            store: Arc::new(store),
        })
    }

    /// Resolve the name of a domain from its ID.
    ///
    /// The files are named by domain name, the trait works in domain IDs.
    /// Returns `None` when no such domain exists, which every read path turns
    /// into "no configuration".
    async fn domain_name(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<Option<String>, DomainConfigProviderError> {
        let ctx = ExecutionContext::internal(state);
        let domain = state
            .provider
            .get_resource_provider()
            .get_domain(&ctx, domain_id)
            .await
            .map_err(|err| DomainConfigProviderError::Driver(err.to_string()))?;
        Ok(domain.map(|domain| domain.name))
    }
}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping this crate's `inventory::submit!` visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

// Submit the plugin to the registry at compile-time.
inventory::submit! {
    BackendRegistration::<dyn DomainConfigBackend> {
        name: "fs",
        selected: |_| true,
        build: |cfg: &Config| {
            let backend = FsBackend::new(cfg);
            Box::pin(async move {
                Ok(Arc::new(backend?) as Arc<dyn DomainConfigBackend>)
            })
        },
    }
}

#[async_trait]
impl DomainConfigBackend for FsBackend {
    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn create_domain_config<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
        _config: DomainConfigCreate,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        Err(readonly("create a domain configuration"))
    }

    /// The whole configuration of a domain, sensitive options included so the
    /// identity backend can bind. [`DomainConfig`] drops them on serialization.
    async fn get_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<DomainConfig>, DomainConfigProviderError> {
        let Some(name) = self.domain_name(state, domain_id).await? else {
            return Ok(None);
        };
        get::get_config(&self.store, &name)
    }

    /// A single group, with sensitive options filtered out.
    async fn get_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<Option<DomainConfigGroup>, DomainConfigProviderError> {
        let Some(name) = self.domain_name(state, domain_id).await? else {
            return Ok(None);
        };
        get::get_group(&self.store, &name, group)
    }

    /// A single option; `None` for a sensitive one, which is never readable.
    async fn get_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
        let Some(name) = self.domain_name(state, domain_id).await? else {
            return Ok(None);
        };
        get::get_option(&self.store, &name, group, option)
    }

    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn update_domain_config<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
        _config: DomainConfigUpdate,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        Err(readonly("update a domain configuration"))
    }

    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn update_domain_config_group<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
        _group: DomainConfigGroupName,
        _config: DomainConfigUpdate,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError> {
        Err(readonly("update a domain configuration group"))
    }

    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn update_domain_config_option<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
        _option: DomainConfigOption,
    ) -> Result<DomainConfigOption, DomainConfigProviderError> {
        Err(readonly("update a domain configuration option"))
    }

    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn delete_domain_config<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
    ) -> Result<(), DomainConfigProviderError> {
        Err(readonly("delete a domain configuration"))
    }

    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn delete_domain_config_group<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
        _group: DomainConfigGroupName,
    ) -> Result<(), DomainConfigProviderError> {
        Err(readonly("delete a domain configuration group"))
    }

    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn delete_domain_config_option<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
        _group: DomainConfigGroupName,
        _option: &'a str,
    ) -> Result<(), DomainConfigProviderError> {
        Err(readonly("delete a domain configuration option"))
    }

    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn obtain_registration<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
        _driver_type: &'a str,
    ) -> Result<bool, DomainConfigProviderError> {
        Err(readonly("obtain a configuration registration"))
    }

    /// A file backend keeps no registration; nobody holds one.
    async fn read_registration<'a>(
        &self,
        _state: &ServiceState,
        _driver_type: &'a str,
    ) -> Result<Option<String>, DomainConfigProviderError> {
        Ok(None)
    }

    /// Read-only: always [`DomainConfigProviderError::Readonly`].
    async fn release_registration<'a>(
        &self,
        _state: &ServiceState,
        _domain_id: &'a str,
        _driver_type: Option<&'a str>,
    ) -> Result<(), DomainConfigProviderError> {
        Err(readonly("release a configuration registration"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The driver registers under `fs`, is always selected, and builds when
    /// the configured directory is absent (the default).
    #[tokio::test]
    async fn registers_and_builds_with_no_directory() {
        let registration = inventory::iter::<BackendRegistration<dyn DomainConfigBackend>>()
            .into_iter()
            .find(|registration| registration.name == "fs")
            .expect("the filesystem driver registers under `fs`");

        let config = Config::default();
        assert!((registration.selected)(&config));
        assert!((registration.build)(&config).await.is_ok());
    }
}
