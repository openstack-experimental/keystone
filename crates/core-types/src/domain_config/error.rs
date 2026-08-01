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

//! # Domain configuration provider errors

use thiserror::Error;

use crate::error::BuilderError;

/// Domain configuration provider error.
///
/// The `Unsupported*` and `Empty*` variants correspond to python-keystone's
/// `InvalidDomainConfig`, which the v3 API reports as `403 Forbidden` (see
/// `api-ref/source/v3/domains-config-v3.inc`: "If you try to create or update
/// configuration options for groups other than the `identity` or `ldap`
/// groups, the `Forbidden (403)` response code is returned"). [`Self::NotFound`]
/// corresponds to `DomainConfigNotFound` (`404`).
#[derive(Error, Debug)]
pub enum DomainConfigProviderError {
    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

    /// The request carried no configuration at all.
    #[error("no options specified")]
    EmptyConfig,

    /// A group in the request did not carry a mapping of options.
    #[error("the value of group {0} specified in the config should be a dictionary of options")]
    GroupNotAMapping(String),

    /// A stored (or supplied) option value has a type the option cannot hold,
    /// and the offending option could be pinpointed.
    #[error("invalid value for option {option} in group {group}: {source}")]
    InvalidOptionValue {
        /// The group holding the offending option.
        group: String,
        /// The offending option.
        option: String,
        /// The underlying (de)serialization failure.
        #[source]
        source: serde_json::Error,
    },

    /// A group could not be decoded and no single option accounts for it.
    #[error("invalid value for an option of the group {group}: {source}")]
    InvalidValue {
        /// The group that could not be decoded.
        group: String,
        /// The underlying (de)serialization failure.
        #[source]
        source: serde_json::Error,
    },

    /// No configuration exists for the requested domain/group/option.
    #[error("could not find {group_or_option} for domain {domain_id}")]
    NotFound {
        /// The domain the lookup was scoped to.
        domain_id: String,
        /// Human readable description of what was looked up, e.g.
        /// `option url in group ldap` or `any options`.
        group_or_option: String,
    },

    /// An option was specified without its group. The API routing makes this
    /// impossible, so it always indicates a coding error.
    #[error("option {0} found with no group specified while checking domain configuration request")]
    OptionWithoutGroup(String),

    /// (de)serialization error.
    #[error("data serialization error")]
    Serde {
        /// The source of the error.
        #[from]
        source: serde_json::Error,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: BuilderError,
    },

    /// The requested group is not one of the domain-configurable groups.
    #[error("group {0} is not supported for domain specific configurations")]
    UnsupportedGroup(String),

    /// The requested option is not whitelisted (nor sensitive) in its group.
    #[error("option {option} in group {group} is not supported for domain specific configurations")]
    UnsupportedOption {
        /// The group the option was looked up in.
        group: String,
        /// The rejected option name.
        option: String,
    },

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the domain config provider")]
    UnsupportedDriver(String),

    /// Request validation error.
    #[error("request validation error: {}", source)]
    Validation {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },
}

impl DomainConfigProviderError {
    /// Build a [`Self::NotFound`] for a whole domain configuration.
    ///
    /// # Parameters
    /// - `domain_id`: The domain the configuration was looked up for.
    ///
    /// # Returns
    /// - `Self` - The `NotFound` error with python-keystone's `any options`
    ///   wording.
    pub fn config_not_found<D: Into<String>>(domain_id: D) -> Self {
        Self::NotFound {
            domain_id: domain_id.into(),
            group_or_option: "any options".to_string(),
        }
    }

    /// Build a [`Self::NotFound`] for a single group.
    ///
    /// # Parameters
    /// - `domain_id`: The domain the configuration was looked up for.
    /// - `group`: The group that has no stored options.
    ///
    /// # Returns
    /// - `Self` - The `NotFound` error.
    pub fn group_not_found<D: Into<String>, G: std::fmt::Display>(domain_id: D, group: G) -> Self {
        Self::NotFound {
            domain_id: domain_id.into(),
            group_or_option: format!("group {group}"),
        }
    }

    /// Build a [`Self::NotFound`] for a single option.
    ///
    /// # Parameters
    /// - `domain_id`: The domain the configuration was looked up for.
    /// - `group`: The group the option belongs to.
    /// - `option`: The option that has no stored value.
    ///
    /// # Returns
    /// - `Self` - The `NotFound` error.
    pub fn option_not_found<D: Into<String>, G: std::fmt::Display, O: std::fmt::Display>(
        domain_id: D,
        group: G,
        option: O,
    ) -> Self {
        Self::NotFound {
            domain_id: domain_id.into(),
            group_or_option: format!("option {option} in group {group}"),
        }
    }
}
