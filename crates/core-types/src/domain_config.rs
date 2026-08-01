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

//! # Domain configuration provider types
//!
//! Per-domain overrides of the identity backend configuration, as exposed by
//! the `/v3/domains/{domain_id}/config` API family.
//!
//! The data model mirrors python-keystone's
//! `keystone.resource.core.DomainConfigManager`:
//!
//! - configuration is organized into *groups* (`identity` and `ldap` only),
//!   each holding a flat set of *options*,
//! - an option is only storable when it is explicitly listed as either
//!   whitelisted or sensitive (see [`whitelisted_options`] /
//!   [`sensitive_options`]); anything else is dropped with a warning, so
//!   making a new option domain-configurable is always a deliberate act,
//! - sensitive options (today only `ldap.password`) are stored separately and
//!   are never returned by the API: they are stripped on serialization and
//!   redacted in `Debug`.
//!
//! What an option *is* — its type, its default, how a config file spells it —
//! is not restated here. It comes from the config section the option
//! overrides, [`openstack_keystone_config::IdentityProvider`] or
//! [`openstack_keystone_config::LdapProvider`]; see [`DomainConfig`].
//!
//! Values are persisted verbatim as JSON ([`DomainConfigValue`]), matching
//! python-keystone's `JsonBlob` columns.

mod config;
mod error;
mod lenient;
mod option;

pub use config::*;
pub use error::*;
pub use option::*;
