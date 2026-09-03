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

//! # The read paths
//!
//! Same shape and same sensitive-option handling as
//! `openstack-keystone-domain-config-driver-sql`'s `get` module: the
//! whole-config read hands back sensitive options (the identity backend needs
//! the bind password and [`DomainConfig`] strips it on the wire), the
//! group- and option-scoped reads never do.

use openstack_keystone_core_types::domain_config::{
    DomainConfig, DomainConfigGroup, DomainConfigGroupName, DomainConfigOption,
    DomainConfigProviderError, is_sensitive,
};

use crate::store::DomainConfigStore;

/// The whole configuration of a domain, or `None` when no file supplied one.
pub(crate) fn get_config(
    store: &DomainConfigStore,
    domain_name: &str,
) -> Result<Option<DomainConfig>, DomainConfigProviderError> {
    Ok(store.get(domain_name).cloned())
}

/// A single group with its sensitive options removed, or `None` when nothing
/// readable remains (no file, no such group, or the group holds only
/// sensitive options).
pub(crate) fn get_group(
    store: &DomainConfigStore,
    domain_name: &str,
    group: DomainConfigGroupName,
) -> Result<Option<DomainConfigGroup>, DomainConfigProviderError> {
    let Some(config) = store.get(domain_name) else {
        return Ok(None);
    };
    let Some(stored) = config.group(group) else {
        return Ok(None);
    };

    let readable = DomainConfigGroup::from_options(
        group,
        stored
            .options()
            .iter()
            .filter(|(option, _)| !is_sensitive(group, option))
            .map(|(option, value)| DomainConfigOption::new(group, option.clone(), value.clone())),
    )?;

    if readable.is_empty() {
        Ok(None)
    } else {
        Ok(Some(readable))
    }
}

/// A single option, or `None`. A sensitive option is never returned, so it is
/// `None` without even consulting the store.
pub(crate) fn get_option(
    store: &DomainConfigStore,
    domain_name: &str,
    group: DomainConfigGroupName,
    option: &str,
) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
    if is_sensitive(group, option) {
        return Ok(None);
    }
    Ok(store
        .get(domain_name)
        .and_then(|config| config.group(group))
        .and_then(|stored| stored.get(option))
        .map(|value| DomainConfigOption::new(group, option, value.clone())))
}

#[cfg(test)]
#[path = "get/tests.rs"]
mod tests;
