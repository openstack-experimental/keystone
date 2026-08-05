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

//! # Domain configuration structures
//!
//! A domain configuration is a set of *overrides* of the global `[identity]`
//! and `[ldap]` config sections, so it is held as the options a domain
//! actually set — `group -> option -> value`, values verbatim as JSON, the
//! way the persistence layer stores them — rather than as a second set of
//! structs mirroring those sections.
//!
//! What the options *mean* is defined once, by
//! [`openstack_keystone_config::IdentityProvider`] and
//! [`openstack_keystone_config::LdapProvider`]:
//!
//! - [`DomainConfig::resolve_identity`] / [`DomainConfig::resolve_ldap`]
//!   overlay a domain's options onto the global section and hand back the very
//!   struct the identity backend is configured with;
//! - [`DomainConfig::defaults`] serializes the global sections and keeps the
//!   whitelisted keys, which is what the `/v3/domains/config/…/default`
//!   endpoints answer;
//! - [`DomainConfig::validate_values`] checks a client's values by decoding
//!   them into those same structs.
//!
//! The only thing this module states about an individual option is whether a
//! domain may set it at all (see [`super::whitelisted_options`]) — names, not
//! types. An option added to `LdapProvider` therefore cannot drift from its
//! domain-configurable counterpart, because there is no counterpart.

use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::{Deref, DerefMut};

use openstack_keystone_config::{Config, IdentityProvider, LdapProvider};
use serde::de::DeserializeOwned;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::lenient;
use super::{
    DomainConfigGroupName, DomainConfigOption, DomainConfigProviderError, DomainConfigValue,
};

/// One configuration group with the options a domain set in it.
///
/// Returned by the group-scoped endpoints
/// (`/v3/domains/{domain_id}/config/{group}`), which address exactly one
/// group.
#[derive(Clone)]
pub struct DomainConfigGroup {
    /// The group these options belong to.
    name: DomainConfigGroupName,
    /// The options, by name.
    options: Map<String, Value>,
}

impl DomainConfigGroup {
    /// An empty group.
    ///
    /// # Parameters
    /// - `name`: The group.
    ///
    /// # Returns
    /// - `Self` - The group with no option set.
    pub fn new(name: DomainConfigGroupName) -> Self {
        Self {
            name,
            options: Map::new(),
        }
    }

    /// Name of the group.
    ///
    /// # Returns
    /// - `DomainConfigGroupName` - The group discriminant.
    pub fn name(&self) -> DomainConfigGroupName {
        self.name
    }

    /// The options set in the group.
    ///
    /// Sensitive options are included; see [`Self::serialize`] for what
    /// reaches a response.
    ///
    /// # Returns
    /// - `&Map<String, Value>` - The options by name.
    pub fn options(&self) -> &Map<String, Value> {
        &self.options
    }

    /// Read a single option.
    ///
    /// # Parameters
    /// - `option`: The option name.
    ///
    /// # Returns
    /// - `Option<&Value>` - The value when the domain set the option.
    pub fn get(&self, option: &str) -> Option<&Value> {
        self.options.get(option)
    }

    /// Set a single option.
    ///
    /// # Parameters
    /// - `option`: The option name.
    /// - `value`: The value to store.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())`, or
    ///   [`DomainConfigProviderError::UnsupportedOption`] when the option is
    ///   neither whitelisted nor sensitive in this group.
    pub fn set<O: Into<String>, V: Into<Value>>(
        &mut self,
        option: O,
        value: V,
    ) -> Result<(), DomainConfigProviderError> {
        let option = option.into();
        if !super::is_supported(self.name, &option) {
            return Err(DomainConfigProviderError::UnsupportedOption {
                group: self.name.to_string(),
                option,
            });
        }
        self.options.insert(option, value.into());
        Ok(())
    }

    /// Whether the group carries no option at all.
    ///
    /// # Returns
    /// - `bool` - `true` when every option, sensitive ones included, is unset.
    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }

    /// Build a group from a client supplied object.
    ///
    /// Unsupported options are dropped with a warning rather than rejected,
    /// which is what python-keystone's `_config_to_list` does with them.
    ///
    /// # Parameters
    /// - `name`: The group being built.
    /// - `value`: The options object.
    ///
    /// # Returns
    /// - `Result<Self, DomainConfigProviderError>` - The group, or
    ///   [`DomainConfigProviderError::GroupNotAMapping`] when the value is not
    ///   an object.
    pub fn from_value(
        name: DomainConfigGroupName,
        value: Value,
    ) -> Result<Self, DomainConfigProviderError> {
        let Value::Object(options) = value else {
            return Err(DomainConfigProviderError::GroupNotAMapping(
                name.to_string(),
            ));
        };
        Ok(Self {
            name,
            options: retain_supported(name, options),
        })
    }

    /// Build a group from the options stored for it.
    ///
    /// Like [`DomainConfig::from_options`], this is the read path and skips
    /// stored options it does not recognize. An option belonging to a
    /// *different* group is still an error: that is a caller mistake rather
    /// than data drift.
    ///
    /// # Parameters
    /// - `name`: The group being built.
    /// - `options`: The stored options; every one must belong to `name`.
    ///
    /// # Returns
    /// - `Result<Self, DomainConfigProviderError>` - The group, or an error
    ///   when an option belongs to another group.
    pub fn from_options<I>(
        name: DomainConfigGroupName,
        options: I,
    ) -> Result<Self, DomainConfigProviderError>
    where
        I: IntoIterator<Item = DomainConfigOption>,
    {
        let mut group = Self::new(name);
        for option in options {
            if option.group != name {
                return Err(DomainConfigProviderError::UnsupportedOption {
                    group: name.to_string(),
                    option: option.option,
                });
            }
            if !super::is_supported(name, &option.option) {
                warn_unsupported(name, &option.option, "stored");
                continue;
            }
            group.options.insert(option.option, option.value.into());
        }
        Ok(group)
    }

    /// Flatten the group into stored options.
    ///
    /// # Returns
    /// - `Vec<DomainConfigOption>` - One entry per set option, sensitive ones
    ///   flagged as such.
    pub fn to_options(&self) -> Vec<DomainConfigOption> {
        self.options
            .iter()
            .map(|(option, value)| {
                DomainConfigOption::new(
                    self.name,
                    option.clone(),
                    DomainConfigValue::from(value.clone()),
                )
            })
            .collect()
    }

    /// Check that every option holds a value its option can take.
    ///
    /// The check is the config section this group overrides: an option is
    /// validated by the same declaration the running service is configured
    /// from, so a new option needs nothing added here.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())`, or
    ///   [`DomainConfigProviderError::InvalidOptionValue`] naming the option
    ///   that cannot be decoded.
    pub fn validate_values(&self) -> Result<(), DomainConfigProviderError> {
        match self.name {
            DomainConfigGroupName::Identity => {
                decode_group::<IdentityProvider>(self)?;
            }
            DomainConfigGroupName::Ldap => {
                decode_group::<LdapProvider>(self)?;
            }
        }
        Ok(())
    }

    /// Widen the group into a configuration holding only it.
    ///
    /// # Returns
    /// - `DomainConfig` - A configuration with just this group populated.
    pub fn into_config(self) -> DomainConfig {
        DomainConfig {
            groups: BTreeMap::from([(self.name, self)]),
        }
    }

    /// The options a response may carry.
    ///
    /// # Returns
    /// - `impl Iterator<Item = (&String, &Value)>` - Every option that is not
    ///   sensitive.
    fn readable(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.options
            .iter()
            .filter(|(option, _)| !super::is_sensitive(self.name, option))
    }
}

impl Serialize for DomainConfigGroup {
    /// Serialize the readable options.
    ///
    /// Sensitive options are dropped: the same structure serves the internal,
    /// fully resolved configuration and the API response, so a bind password
    /// must not be able to reach the wire through it.
    ///
    /// # Parameters
    /// - `serializer`: The serde serializer.
    ///
    /// # Returns
    /// - `Result<S::Ok, S::Error>` - The serialized group.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (option, value) in self.readable() {
            map.serialize_entry(option, value)?;
        }
        map.end()
    }
}

impl fmt::Debug for DomainConfigGroup {
    /// Redact the value of sensitive options so they cannot reach logs or
    /// traces through a `{:?}` of the surrounding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_map();
        for (option, value) in &self.options {
            if super::is_sensitive(self.name, option) {
                out.entry(option, &"REDACTED");
            } else {
                out.entry(option, value);
            }
        }
        out.finish()
    }
}

/// The configuration of a single domain.
///
/// This is the body of `{"config": {...}}` in the v3 API. Sensitive options it
/// carries (`ldap.password`) are stripped on serialization and redacted in
/// `Debug`, so the same structure serves both the internal, fully resolved
/// configuration and the API response.
#[derive(Clone, Default)]
pub struct DomainConfig {
    /// The configured groups, in a stable order.
    groups: BTreeMap<DomainConfigGroupName, DomainConfigGroup>,
}

impl DomainConfig {
    /// An empty configuration.
    ///
    /// # Returns
    /// - `Self` - A configuration with no group.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the configuration carries no option at all.
    ///
    /// # Returns
    /// - `bool` - `true` when no group holds a single option.
    pub fn is_empty(&self) -> bool {
        self.groups.values().all(DomainConfigGroup::is_empty)
    }

    /// The configured groups.
    ///
    /// # Returns
    /// - `impl Iterator<Item = &DomainConfigGroup>` - The groups, `identity`
    ///   before `ldap`.
    pub fn groups(&self) -> impl Iterator<Item = &DomainConfigGroup> {
        self.groups.values()
    }

    /// Borrow a single group.
    ///
    /// # Parameters
    /// - `name`: The group to look up.
    ///
    /// # Returns
    /// - `Option<&DomainConfigGroup>` - The group when it is present.
    pub fn group(&self, name: DomainConfigGroupName) -> Option<&DomainConfigGroup> {
        self.groups.get(&name)
    }

    /// Take a single group out of the configuration.
    ///
    /// # Parameters
    /// - `name`: The group to extract.
    ///
    /// # Returns
    /// - `Option<DomainConfigGroup>` - The group when it is present.
    pub fn into_group(mut self, name: DomainConfigGroupName) -> Option<DomainConfigGroup> {
        self.groups.remove(&name)
    }

    /// Add a group, replacing one of the same name.
    ///
    /// # Parameters
    /// - `group`: The group to insert.
    pub fn insert(&mut self, group: DomainConfigGroup) {
        self.groups.insert(group.name, group);
    }

    /// Set a single option, creating its group when needed.
    ///
    /// # Parameters
    /// - `group`: The group holding the option.
    /// - `option`: The option name.
    /// - `value`: The value to store.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())`, or
    ///   [`DomainConfigProviderError::UnsupportedOption`].
    pub fn set<O: Into<String>, V: Into<Value>>(
        &mut self,
        group: DomainConfigGroupName,
        option: O,
        value: V,
    ) -> Result<(), DomainConfigProviderError> {
        self.groups
            .entry(group)
            .or_insert_with(|| DomainConfigGroup::new(group))
            .set(option, value)
    }

    /// Build a configuration from a client supplied object.
    ///
    /// The payload is checked the way python-keystone's `_assert_valid_config`
    /// checks it — at least one group, each group a non-empty mapping — and
    /// unsupported *options* are then dropped with a warning, as
    /// `_config_to_list` does. An unsupported *group* is an error, because the
    /// api-ref promises a `403` for one.
    ///
    /// # Parameters
    /// - `value`: The `config` object of the request body.
    ///
    /// # Returns
    /// - `Result<Self, DomainConfigProviderError>` - The configuration, or the
    ///   error the request should be rejected with.
    pub fn from_value(value: Value) -> Result<Self, DomainConfigProviderError> {
        let Value::Object(groups) = value else {
            return Err(DomainConfigProviderError::EmptyConfig);
        };
        if groups.is_empty() {
            return Err(DomainConfigProviderError::EmptyConfig);
        }
        let mut config = Self::new();
        for (name, options) in groups {
            let name: DomainConfigGroupName = name.parse()?;
            // The shape is checked before the option names are looked at, the
            // order python-keystone checks them in: a group left empty by the
            // whitelist is not the same thing as one that arrived empty, and
            // only the latter is an error.
            match &options {
                Value::Object(options) if !options.is_empty() => {}
                _ => {
                    return Err(DomainConfigProviderError::GroupNotAMapping(
                        name.to_string(),
                    ));
                }
            }
            config.insert(DomainConfigGroup::from_value(name, options)?);
        }
        Ok(config)
    }

    /// Validate a configuration a driver is about to store.
    ///
    /// Half of python-keystone's `DomainConfigManager._assert_valid_config`:
    /// the request must address at least one group. The other half — a group
    /// must be a *non-empty* mapping — is checked by [`Self::from_value`], on
    /// the payload as it arrived. Checking it again here would reject the
    /// request python-keystone accepts: a group holding nothing but options
    /// outside the whitelist is left empty on purpose, and stores nothing.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())` when the payload is
    ///   usable, otherwise [`DomainConfigProviderError::EmptyConfig`].
    pub fn validate(&self) -> Result<(), DomainConfigProviderError> {
        if self.groups.is_empty() {
            return Err(DomainConfigProviderError::EmptyConfig);
        }
        Ok(())
    }

    /// Check that every option holds a value its option can take.
    ///
    /// The check is the config structs themselves: each group is decoded into
    /// the section it overrides, so an option is validated by the same
    /// declaration the running service is configured from, and a new option
    /// needs nothing added here.
    ///
    /// # Returns
    /// - `Result<(), DomainConfigProviderError>` - `Ok(())`, or
    ///   [`DomainConfigProviderError::InvalidOptionValue`] naming the option
    ///   that cannot be decoded.
    pub fn validate_values(&self) -> Result<(), DomainConfigProviderError> {
        self.groups
            .values()
            .try_for_each(DomainConfigGroup::validate_values)
    }

    /// Build a configuration from the flat option list a driver stores.
    ///
    /// This is the read path, so it is deliberately tolerant of rows it does
    /// not recognize: a stored option that is no longer whitelisted is skipped
    /// with a warning rather than failing the whole configuration, which would
    /// otherwise leave the domain unreadable — and its identity backend
    /// uninitializable — until an operator deleted the row. python-keystone's
    /// `_list_to_config` likewise does not re-validate on read; the whitelist
    /// is enforced on the write path instead.
    ///
    /// # Parameters
    /// - `options`: The stored options across all groups.
    ///
    /// # Returns
    /// - `Self` - The configuration.
    pub fn from_options<I>(options: I) -> Self
    where
        I: IntoIterator<Item = DomainConfigOption>,
    {
        let mut config = Self::new();
        for option in options {
            if !super::is_supported(option.group, &option.option) {
                warn_unsupported(option.group, &option.option, "stored");
                continue;
            }
            config
                .groups
                .entry(option.group)
                .or_insert_with(|| DomainConfigGroup::new(option.group))
                .options
                .insert(option.option, option.value.into());
        }
        config
    }

    /// Flatten the configuration into the option list a driver stores.
    ///
    /// # Returns
    /// - `Vec<DomainConfigOption>` - One entry per set option, sensitive ones
    ///   flagged as such.
    pub fn to_options(&self) -> Vec<DomainConfigOption> {
        self.groups
            .values()
            .flat_map(DomainConfigGroup::to_options)
            .collect()
    }

    /// The domain's `[identity]` section: the global one with the domain's
    /// overrides applied.
    ///
    /// # Parameters
    /// - `config`: The running service configuration.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, DomainConfigProviderError>` - The resolved
    ///   section, or an error naming the option that could not be decoded.
    pub fn resolve_identity(
        &self,
        config: &Config,
    ) -> Result<IdentityProvider, DomainConfigProviderError> {
        let mut identity: IdentityProvider =
            self.resolve(DomainConfigGroupName::Identity, &config.identity)?;
        // `list_limit` is whitelisted as python-keystone spells it, the page
        // size on its own, so overriding it replaces the whole option and with
        // it the operator's `max_list_limit` — which has no domain-settable
        // spelling of its own. Overriding the page size must not lift the cap
        // on what a client can ask for.
        if identity.list_limit.max_list_limit.is_none() {
            identity.list_limit.max_list_limit = config.identity.list_limit.max_list_limit;
        }
        Ok(identity)
    }

    /// The domain's `[ldap]` section: the global one with the domain's
    /// overrides applied.
    ///
    /// `%(option)s` references are *not* expanded here; run
    /// [`Self::substitute`] first when the configuration comes from storage
    /// and may carry them.
    ///
    /// # Parameters
    /// - `config`: The running service configuration.
    ///
    /// # Returns
    /// - `Result<LdapProvider, DomainConfigProviderError>` - The resolved
    ///   section, or an error naming the option that could not be decoded.
    fn resolve_ldap(&self, config: &Config) -> Result<LdapProvider, DomainConfigProviderError> {
        let domain_overrides_password = self
            .group(DomainConfigGroupName::Ldap)
            .is_some_and(|group| group.get("password").is_some());
        let mut ldap: LdapProvider = self.resolve(DomainConfigGroupName::Ldap, &config.ldap)?;
        // The bind password is never serialized, so the overlay cannot carry
        // the global one. Inherit it only when the domain did not address the
        // option at all: an explicit null requests an anonymous bind.
        if !domain_overrides_password {
            ldap.password.clone_from(&config.ldap.password);
        }
        Ok(ldap)
    }

    /// Overlay a group onto the global section it overrides.
    ///
    /// # Parameters
    /// - `name`: The group to apply.
    /// - `section`: The global config section.
    ///
    /// # Returns
    /// - `Result<T, DomainConfigProviderError>` - The resolved section.
    fn resolve<T: Clone + Serialize + DeserializeOwned>(
        &self,
        name: DomainConfigGroupName,
        section: &T,
    ) -> Result<T, DomainConfigProviderError> {
        let Some(group) = self.groups.get(&name) else {
            return Ok(section.clone());
        };
        let Value::Object(mut merged) = serde_json::to_value(section)? else {
            return Err(DomainConfigProviderError::GroupNotAMapping(
                name.to_string(),
            ));
        };
        for (option, value) in &group.options {
            merged.insert(option.clone(), value.clone());
        }
        lenient::from_value(Value::Object(merged)).map_err(|source| {
            // Pinpoint the offending option the way `decode_group` does.
            decode_group::<T>(group)
                .err()
                .unwrap_or(DomainConfigProviderError::InvalidValue {
                    group: name.to_string(),
                    source,
                })
        })
    }

    /// Resolve `%(option)s` references between the options of a group.
    ///
    /// A whitelisted option may reference another option of the same group,
    /// most usefully a sensitive one, so that a bind password appears in the
    /// stored `ldap.url` only as `%(password)s`:
    ///
    /// ```text
    /// ldap://%(user)s:%(password)s@ldap.example.com:389/
    /// ```
    ///
    /// The result is a [`ResolvedDomainConfig`], which cannot be serialized:
    /// the raw, unsubstituted value is what the config endpoints return, while
    /// the resolved one exists so the identity backend can be handed a usable
    /// connection string and has secrets inlined into options that are
    /// otherwise readable. This is why substitution is a separate step rather
    /// than part of a driver read: `DomainConfigBackend::get_domain_config`
    /// serves the API too.
    ///
    /// Port of python-keystone's substitution pass in
    /// `DomainConfigManager.get_config_with_sensitive_info`, with two
    /// deliberate differences:
    ///
    /// - references resolve against every option of the group, not only the
    ///   sensitive ones, so that the `%(user)s` of the example above resolves
    ///   too;
    /// - a reference that cannot be resolved, or a value whose `%` escapes are
    ///   malformed, leaves *that value* untouched with a warning, matching what
    ///   python-keystone does when the `%` operator raises.
    ///
    /// # Returns
    /// - `ResolvedDomainConfig` - The configuration with every reference
    ///   resolved.
    pub fn substitute(&self) -> ResolvedDomainConfig {
        let options = self.to_options();
        let mut references: HashMap<DomainConfigGroupName, HashMap<&str, String>> = HashMap::new();
        for option in &options {
            // Sensitive options win: a name can only be spelled in one of the
            // two lists, so this only guards against stored drift.
            let entry = references
                .entry(option.group)
                .or_default()
                .entry(option.option.as_str());
            match entry {
                Entry::Vacant(slot) => {
                    slot.insert(option.value.to_string());
                }
                Entry::Occupied(mut slot) if option.sensitive() => {
                    slot.insert(option.value.to_string());
                }
                Entry::Occupied(_) => {}
            }
        }

        let substituted = options.iter().map(|option| {
            // Only whitelisted string values are expanded: a secret is used
            // verbatim, and a number or a list has nothing to expand.
            let (Some(text), false) = (option.value.as_str(), option.sensitive()) else {
                return option.clone();
            };
            let resolved = references
                .get(&option.group)
                .map_or(Cow::Borrowed(text), |group| {
                    substitute_references(option.group, &option.option, text, group)
                });
            match resolved {
                Cow::Borrowed(_) => option.clone(),
                Cow::Owned(resolved) => {
                    DomainConfigOption::new(option.group, option.option.clone(), resolved)
                }
            }
        });
        ResolvedDomainConfig(Self::from_options(substituted.collect::<Vec<_>>()))
    }

    /// Global defaults for every readable option, as served by
    /// `GET /v3/domains/config/default`.
    ///
    /// The defaults are the running configuration itself, keyed down to the
    /// whitelisted options; an option that is not configured is reported as
    /// `null`, the way python-keystone's `get_config_default` reports it.
    /// Sensitive options are never part of it — `password` is not whitelisted
    /// and is not serialized either.
    ///
    /// # Parameters
    /// - `config`: The running service configuration.
    ///
    /// # Returns
    /// - `Result<Self, DomainConfigProviderError>` - The defaults of both
    ///   groups, or a serialization error.
    pub fn defaults(config: &Config) -> Result<Self, DomainConfigProviderError> {
        let mut identity = DomainConfigGroup {
            name: DomainConfigGroupName::Identity,
            options: whitelisted_only(
                DomainConfigGroupName::Identity,
                serde_json::to_value(&config.identity)?,
            )?,
        };
        // `[identity] list_limit` falls back to the global `[DEFAULT]
        // list_limit`, the same chain `Config::resolve_list_limit` applies.
        // Reporting only the section-local value would tell an operator `null`
        // while their listings are really capped.
        identity.options.insert(
            "list_limit".to_string(),
            match config
                .identity
                .list_limit
                .list_limit
                .or(config.default.list_limit)
            {
                Some(limit) => Value::from(limit),
                None => Value::Null,
            },
        );

        let ldap = DomainConfigGroup {
            name: DomainConfigGroupName::Ldap,
            options: whitelisted_only(
                DomainConfigGroupName::Ldap,
                serde_json::to_value(&config.ldap)?,
            )?,
        };

        let mut defaults = Self::new();
        defaults.insert(identity);
        defaults.insert(ldap);
        Ok(defaults)
    }

    /// Global defaults of a single group.
    ///
    /// # Parameters
    /// - `config`: The running service configuration.
    /// - `group`: The group to report.
    ///
    /// # Returns
    /// - `Result<DomainConfigGroup, DomainConfigProviderError>` - The defaults
    ///   of the group.
    pub fn default_group(
        config: &Config,
        group: DomainConfigGroupName,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError> {
        Self::defaults(config)?
            .into_group(group)
            // `defaults` populates every group.
            .ok_or_else(|| DomainConfigProviderError::UnsupportedGroup(group.to_string()))
    }

    /// Global defaults as a flat option list.
    ///
    /// Every whitelisted option is present, in whitelist order, with a JSON
    /// `null` value when nothing is configured for it.
    ///
    /// # Parameters
    /// - `config`: The running service configuration.
    /// - `group`: Restrict the result to a single group, or `None` for all.
    ///
    /// # Returns
    /// - `Result<Vec<DomainConfigOption>, DomainConfigProviderError>` - The
    ///   defaults in whitelist order, or a serialization error.
    pub fn default_options(
        config: &Config,
        group: Option<DomainConfigGroupName>,
    ) -> Result<Vec<DomainConfigOption>, DomainConfigProviderError> {
        let defaults = Self::defaults(config)?;
        let mut options = Vec::new();
        for name in DomainConfigGroupName::ALL
            .iter()
            .copied()
            .filter(|name| group.is_none_or(|wanted| wanted == *name))
        {
            let configured = defaults.group(name);
            options.extend(super::whitelisted_options(name).iter().map(|option| {
                DomainConfigOption::new(
                    name,
                    *option,
                    configured
                        .and_then(|group| group.get(option))
                        .cloned()
                        .unwrap_or(Value::Null),
                )
            }));
        }
        Ok(options)
    }

    /// Default value of a single option, as served by
    /// `GET /v3/domains/config/{group}/{option}/default`.
    ///
    /// # Parameters
    /// - `config`: The running service configuration.
    /// - `group`: The group holding the option.
    /// - `option`: The option to read.
    ///
    /// # Returns
    /// - `Result<Option<DomainConfigValue>, DomainConfigProviderError>` - The
    ///   default value, or an error when the option is not readable.
    pub fn default_option(
        config: &Config,
        group: DomainConfigGroupName,
        option: &str,
    ) -> Result<Option<DomainConfigValue>, DomainConfigProviderError> {
        // Sensitive options have no readable default: python-keystone builds
        // the default response from the whitelist only.
        if !super::is_whitelisted(group, option) {
            return Err(DomainConfigProviderError::UnsupportedOption {
                group: group.to_string(),
                option: option.to_string(),
            });
        }
        Ok(Self::default_options(config, Some(group))?
            .into_iter()
            .find(|stored| stored.option == option)
            .map(|stored| stored.value))
    }
}

impl Serialize for DomainConfig {
    /// Serialize the readable options of every group.
    ///
    /// A group left with nothing readable — one holding only a bind password —
    /// is omitted rather than reported empty.
    ///
    /// # Parameters
    /// - `serializer`: The serde serializer.
    ///
    /// # Returns
    /// - `Result<S::Ok, S::Error>` - The serialized configuration.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for group in self.groups.values() {
            if group.readable().next().is_none() {
                continue;
            }
            map.serialize_entry(group.name.as_str(), group)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for DomainConfig {
    /// Decode a client supplied `config` object.
    ///
    /// Shares [`DomainConfig::from_value`]'s rules; use that directly to get
    /// the typed error a response needs.
    ///
    /// # Parameters
    /// - `deserializer`: The serde deserializer.
    ///
    /// # Returns
    /// - `Result<Self, D::Error>` - The configuration, or the failure as a
    ///   serde error.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        Self::from_value(Value::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Debug for DomainConfig {
    /// Redact sensitive values; see [`DomainConfigGroup`]'s `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_map();
        for (name, group) in &self.groups {
            out.entry(&name.as_str(), group);
        }
        out.finish()
    }
}

/// A configuration whose `%(option)s` references have been expanded.
///
/// The result of [`DomainConfig::substitute`], and deliberately a type of its
/// own: expansion inlines secrets into options that are otherwise readable —
/// an `ldap.url` spelled `ldap://%(user)s:%(password)s@host` comes out of it
/// carrying the bind password — so it must never reach a response or a log.
/// It therefore implements neither `Serialize` nor `Deref`, and its `Debug`
/// shows nothing; what it is for is [`Self::resolve_ldap`].
#[derive(Clone)]
pub struct ResolvedDomainConfig(DomainConfig);

/// An LDAP section whose option substitutions have been expanded.
///
/// Any string option may now contain a secret, so the ordinary derived
/// [`Debug`](fmt::Debug) implementation of [`LdapProvider`] is not safe for
/// this value. The wrapper stays in place through the provider handoff and
/// redacts the whole section while still allowing read-only use through
/// [`Deref`].
#[derive(Clone)]
pub struct ResolvedLdapProvider(LdapProvider);

impl Deref for ResolvedLdapProvider {
    type Target = LdapProvider;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for ResolvedLdapProvider {
    /// Show nothing: after expansion any field may hold a secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolvedLdapProvider(REDACTED)")
    }
}

impl ResolvedDomainConfig {
    /// The domain's `[identity]` section; see
    /// [`DomainConfig::resolve_identity`].
    ///
    /// # Parameters
    /// - `config`: The running service configuration.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, DomainConfigProviderError>` - The resolved
    ///   section.
    pub fn resolve_identity(
        &self,
        config: &Config,
    ) -> Result<IdentityProvider, DomainConfigProviderError> {
        self.0.resolve_identity(config)
    }

    /// The domain's `[ldap]` section; see [`DomainConfig::resolve_ldap`].
    ///
    /// # Parameters
    /// - `config`: The running service configuration.
    ///
    /// # Returns
    /// - `Result<ResolvedLdapProvider, DomainConfigProviderError>` - The
    ///   resolved section, references expanded and Debug-redacted.
    pub fn resolve_ldap(
        &self,
        config: &Config,
    ) -> Result<ResolvedLdapProvider, DomainConfigProviderError> {
        self.0.resolve_ldap(config).map(ResolvedLdapProvider)
    }

    /// Read a single expanded option.
    ///
    /// Test only: an expanded value may carry a secret whatever its option is
    /// called, so nothing outside these tests gets to pull one out. A consumer
    /// that needs the expanded configuration takes it as a section, through
    /// [`Self::resolve_ldap`].
    ///
    /// # Parameters
    /// - `group`: The group holding the option.
    /// - `option`: The option name.
    ///
    /// # Returns
    /// - `Option<&Value>` - The expanded value when the domain set the option.
    #[cfg(test)]
    pub(crate) fn option(&self, group: DomainConfigGroupName, option: &str) -> Option<&Value> {
        self.0.group(group).and_then(|group| group.get(option))
    }
}

impl fmt::Debug for ResolvedDomainConfig {
    /// Show nothing: after expansion any option may hold a secret, so there is
    /// no subset of this that is safe to log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolvedDomainConfig(REDACTED)")
    }
}

/// Payload of `PUT /v3/domains/{domain_id}/config`.
///
/// A create replaces the domain's stored configuration in full: options absent
/// from the payload are removed.
#[derive(Clone, Debug, Default)]
pub struct DomainConfigCreate(pub DomainConfig);

/// Payload of `PATCH /v3/domains/{domain_id}/config` and of the group- and
/// option-scoped updates.
///
/// An update merges into the stored configuration: options absent from the
/// payload keep their current value.
#[derive(Clone, Debug, Default)]
pub struct DomainConfigUpdate(pub DomainConfig);

macro_rules! domain_config_wrapper {
    ($name:ident) => {
        impl $name {
            /// Consume the wrapper and yield the configuration.
            ///
            /// # Returns
            /// - `DomainConfig` - The wrapped configuration.
            pub fn into_inner(self) -> DomainConfig {
                self.0
            }
        }

        impl From<DomainConfig> for $name {
            fn from(config: DomainConfig) -> Self {
                Self(config)
            }
        }

        impl From<$name> for DomainConfig {
            fn from(wrapper: $name) -> Self {
                wrapper.0
            }
        }

        impl Deref for $name {
            type Target = DomainConfig;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

domain_config_wrapper!(DomainConfigCreate);
domain_config_wrapper!(DomainConfigUpdate);

/// Drop the options of an object a domain may not set.
///
/// # Parameters
/// - `group`: The group the options belong to.
/// - `options`: The supplied options.
///
/// # Returns
/// - `Map<String, Value>` - The supported options.
fn retain_supported(
    group: DomainConfigGroupName,
    options: Map<String, Value>,
) -> Map<String, Value> {
    options
        .into_iter()
        .filter(|(option, _)| {
            let supported = super::is_supported(group, option);
            if !supported {
                warn_unsupported(group, option, "user provided");
            }
            supported
        })
        .collect()
}

/// Keep only the readable options of a serialized config section.
///
/// # Parameters
/// - `group`: The group the section maps to.
/// - `section`: The serialized section.
///
/// # Returns
/// - `Result<Map<String, Value>, DomainConfigProviderError>` - The whitelisted
///   options, or [`DomainConfigProviderError::GroupNotAMapping`] when the
///   section is not an object.
fn whitelisted_only(
    group: DomainConfigGroupName,
    section: Value,
) -> Result<Map<String, Value>, DomainConfigProviderError> {
    let Value::Object(options) = section else {
        return Err(DomainConfigProviderError::GroupNotAMapping(
            group.to_string(),
        ));
    };
    Ok(options
        .into_iter()
        .filter(|(option, _)| super::is_whitelisted(group, option))
        .collect())
}

/// Decode a group into the config section it overrides.
///
/// serde reports a failing value without naming the field it came from, which
/// on a 50 option group leaves an operator guessing. On failure we therefore
/// retry option by option — only on the error path, and each retry is a
/// single-entry map — so the message can name the culprit.
///
/// # Parameters
/// - `group`: The group to decode.
///
/// # Returns
/// - `Result<T, DomainConfigProviderError>` - The decoded section, or
///   [`DomainConfigProviderError::InvalidOptionValue`] naming the offending
///   option, falling back to [`DomainConfigProviderError::InvalidValue`] when
///   no single option reproduces the failure.
fn decode_group<T: DeserializeOwned>(
    group: &DomainConfigGroup,
) -> Result<T, DomainConfigProviderError> {
    let source = match lenient::from_value(Value::Object(group.options.clone())) {
        Ok(decoded) => return Ok(decoded),
        Err(source) => source,
    };
    for (option, value) in &group.options {
        let mut single = Map::new();
        single.insert(option.clone(), value.clone());
        if let Err(source) = lenient::from_value::<T>(Value::Object(single)) {
            return Err(DomainConfigProviderError::InvalidOptionValue {
                group: group.name.to_string(),
                option: option.clone(),
                // The message quotes the value that was rejected, which a
                // secret's must not be.
                source: match super::is_sensitive(group.name, option) {
                    true => serde::de::Error::custom("the value is not one the option can hold"),
                    false => source,
                },
            });
        }
    }
    Err(DomainConfigProviderError::InvalidValue {
        group: group.name.to_string(),
        // No single option accounts for the failure, so the message cannot be
        // attributed — and therefore cannot be shown to carry no secret.
        source: match group
            .options
            .keys()
            .any(|option| super::is_sensitive(group.name, option))
        {
            true => serde::de::Error::custom("a value is not one its option can hold"),
            false => source,
        },
    })
}

/// Log an option that is neither whitelisted nor sensitive.
///
/// # Parameters
/// - `group`: The group the option was found in.
/// - `option`: The option name.
/// - `origin`: Where the option came from, for the message.
fn warn_unsupported(group: DomainConfigGroupName, option: &str, origin: &str) {
    tracing::warn!(
        group = %group,
        option = %option,
        "ignoring a {origin} domain config option that is neither whitelisted nor sensitive"
    );
}

/// Expand the `%(option)s` references of a single value.
///
/// Only the `s` conversion is accepted, which is the only one python-keystone's
/// values can carry, and `%%` stands for a literal `%`. Anything else is a
/// value the `%` operator would have raised on, so it is left alone.
///
/// # Parameters
/// - `group`: The group of the value, for the warning.
/// - `option`: The option of the value, for the warning.
/// - `text`: The raw value.
/// - `references`: The options of the group, by name.
///
/// # Returns
/// - `Cow<'a, str>` - The expanded value, borrowed when it is unchanged.
fn substitute_references<'a>(
    group: DomainConfigGroupName,
    option: &str,
    text: &'a str,
    references: &HashMap<&str, String>,
) -> Cow<'a, str> {
    if !text.contains('%') {
        return Cow::Borrowed(text);
    }
    let mut resolved = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(marker) = rest.find('%') {
        resolved.push_str(&rest[..marker]);
        let tail = &rest[marker + 1..];
        if let Some(tail) = tail.strip_prefix('%') {
            resolved.push('%');
            rest = tail;
            continue;
        }
        let Some((name, tail)) = tail
            .strip_prefix('(')
            .and_then(|tail| tail.split_once(')'))
            .and_then(|(name, tail)| Some((name, tail.strip_prefix('s')?)))
        else {
            tracing::warn!(
                group = %group,
                option = %option,
                "leaving the value of a domain config option as it is: \
                 it looks like an incorrectly constructed option substitution reference"
            );
            return Cow::Borrowed(text);
        };
        let Some(value) = references.get(name) else {
            tracing::warn!(
                group = %group,
                option = %option,
                reference = %name,
                "leaving the value of a domain config option as it is: \
                 it references an option that is not configured for the domain"
            );
            return Cow::Borrowed(text);
        };
        resolved.push_str(value);
        rest = tail;
    }
    resolved.push_str(rest);
    Cow::Owned(resolved)
}

#[cfg(test)]
#[path = "config/tests.rs"]
mod tests;
