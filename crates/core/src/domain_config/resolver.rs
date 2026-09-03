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

//! # Domain configuration resolution
//!
//! A domain's configuration can come from two places: per-domain files under
//! `[identity] domain_config_dir` (the `fs` driver) and the database (the `sql`
//! driver, written through the config API). python-keystone layers the file
//! configuration first and lets the database one override it; this module does
//! the same, gated by the two `[identity]` switches:
//!
//! - `domain_specific_drivers_enabled` — consult the file source at all;
//! - `domain_configurations_from_database` — consult the database source, which
//!   wins where both set the same option.
//!
//! The result is the raw, still-serializable [`DomainConfig`] the config API
//! returns. A consumer that needs a configuration a driver can use — the
//! identity backend selection of issue #960 — runs
//! [`DomainConfig::substitute`] and then `resolve_identity` / `resolve_ldap`
//! on top of it; those steps inline secrets and so produce a value that must
//! not reach a response, which is why they are deliberately left to the
//! caller.

use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::domain_config::DomainConfig;

use crate::domain_config::backend::DomainConfigBackend;
use crate::domain_config::error::DomainConfigProviderError;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

/// Merges a domain's file-based and database-stored configuration into one.
///
/// Holds a handle to each source it is configured to use; a source that is
/// switched off in `[identity]` is simply `None`, and a resolver with neither
/// resolves every domain to the empty configuration.
pub struct DomainConfigResolver {
    /// The `fs` driver, `Some` when
    /// `[identity] domain_specific_drivers_enabled` is set.
    file: Option<Arc<dyn DomainConfigBackend>>,
    /// The `sql` driver, `Some` when
    /// `[identity] domain_configurations_from_database` is set. Overrides the
    /// file source option by option.
    database: Option<Arc<dyn DomainConfigBackend>>,
}

impl DomainConfigResolver {
    /// Wire the resolver from the running configuration and the registered
    /// domain-config backends.
    ///
    /// # Parameters
    /// - `config`: The running service configuration; its `[identity]`
    ///   switches decide which sources are consulted.
    /// - `plugin_manager`: Provides the `"fs"` / `"sql"` backends by name.
    ///
    /// # Returns
    /// - `Result<Self, DomainConfigProviderError>` - The resolver, or
    ///   [`DomainConfigProviderError::UnsupportedDriver`] when an enabled
    ///   source has no registered backend.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, DomainConfigProviderError> {
        let file = if config.identity.domain_specific_drivers_enabled {
            Some(plugin_manager.get_domain_config_backend("fs")?.clone())
        } else {
            None
        };
        let database = if config.identity.domain_configurations_from_database {
            Some(plugin_manager.get_domain_config_backend("sql")?.clone())
        } else {
            None
        };
        Ok(Self { file, database })
    }

    /// A resolver with no source: every domain resolves to the empty
    /// configuration. Used by the mocked provider builder.
    ///
    /// # Returns
    /// - `Self` - A resolver that consults nothing.
    pub fn disabled() -> Self {
        Self {
            file: None,
            database: None,
        }
    }

    /// The effective stored configuration for a domain: the file source
    /// overlaid by the database source.
    ///
    /// `%(option)s` references are not expanded and the global `[identity]` /
    /// `[ldap]` sections are not applied — the result is the raw overlay the
    /// config API serves. See the module note for the steps a driver-facing
    /// consumer adds.
    ///
    /// # Parameters
    /// - `state`: The current service state, handed to each backend.
    /// - `domain_id`: The ID of the domain to resolve.
    ///
    /// # Returns
    /// - `Result<DomainConfig, DomainConfigProviderError>` - The merged
    ///   configuration, empty when no source has one for the domain, or the
    ///   first error a source returns.
    pub async fn effective_config(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        let mut resolved = DomainConfig::new();
        if let Some(file) = &self.file
            && let Some(stored) = file.get_domain_config(state, domain_id).await?
        {
            resolved.overlay(&stored);
        }
        if let Some(database) = &self.database
            && let Some(stored) = database.get_domain_config(state, domain_id).await?
        {
            resolved.overlay(&stored);
        }
        Ok(resolved)
    }
}

#[cfg(test)]
#[path = "resolver/tests.rs"]
mod tests;
