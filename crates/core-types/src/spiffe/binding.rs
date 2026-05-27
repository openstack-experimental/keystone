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
//! # SPIFFE binding
//!
//! A binding represents a fixed bind between the SPIFFE identity and the
//! OpenStack user and scope.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::error::BuilderError;
use crate::role::RoleRef;

/// Authorization information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum SpiffeAuthorization {
    /// Domain scope.
    Domain {
        /// Domain ID.
        domain_id: String,
        /// Roles to limit the authorization to.
        role_ids: Option<Vec<String>>,
    },
    /// Project scope.
    // TODO: to increase fine-granularity individual policy rules can be listed instead of the
    // roles, but that require a new approach of how to enable protection so that not admin
    // does not get access to the admin-only rule.
    Project {
        /// Project ID.
        project_id: String,
        /// Roles to limit the authorization to.
        role_ids: Option<Vec<String>>,
    },
    /// System authorization
    System {
        /// System ID.
        system_id: String,
        /// Roles to limit the authorization to.
        role_ids: Option<Vec<String>>,
    },
}

impl SpiffeAuthorization {
    /// Return role ids bound by the authorization as a vector or [`RoleRef`].
    pub fn role_refs(&self) -> Option<Vec<RoleRef>> {
        match &self {
            Self::Domain { role_ids, .. } => role_ids.as_ref().map(|rids| {
                rids.iter()
                    .map(|rid| RoleRef {
                        id: rid.clone(),
                        name: None,
                        domain_id: None,
                    })
                    .collect()
            }),
            Self::Project { role_ids, .. } => role_ids.as_ref().map(|rids| {
                rids.iter()
                    .map(|rid| RoleRef {
                        id: rid.clone(),
                        name: None,
                        domain_id: None,
                    })
                    .collect()
            }),
            Self::System { role_ids, .. } => role_ids.as_ref().map(|rids| {
                rids.iter()
                    .map(|rid| RoleRef {
                        id: rid.clone(),
                        name: None,
                        domain_id: None,
                    })
                    .collect()
            }),
        }
    }
}

/// Spiffe identity binding.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct SpiffeBinding {
    /// Bound authorizations.
    #[builder(default)]
    pub authorizations: Option<Vec<SpiffeAuthorization>>,

    /// Domain ID the identity belongs to.
    pub domain_id: String,

    /// SPIFFE SVID.
    pub svid: String,

    /// Flag indicating the system wide identity (system scope). This property
    /// cannot be changed after creation.
    pub is_system: bool,

    /// The ID of the User the identity is mapped to. When not specified a
    /// virtual user_id is being derived from the SVID.
    #[builder(default)]
    pub user_id: Option<String>,
}

/// New binding.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct SpiffeBindingCreate {
    /// Bound authorizations.
    pub authorizations: Option<Vec<SpiffeAuthorization>>,

    /// Domain ID the identity belongs to.
    pub domain_id: String,

    /// SPIFFE SVID.
    pub svid: String,

    /// Flag indicating the system wide identity (system scope). This property
    /// cannot be changed after creation. System bindings are also protected
    /// from deletion.
    pub is_system: bool,

    /// The ID of the User the identity is mapped to. When not specified a
    /// virtual user_id is being derived from the SVID.
    pub user_id: Option<String>,
}

/// Update Spiffe binding.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct SpiffeBindingUpdate {
    /// Bound authorizations.
    pub authorizations: Option<Vec<SpiffeAuthorization>>,
}

/// K8s Auth role list parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
pub struct SpiffeBindingListParameters {
    /// Domain ID the filter identity bindings.
    pub domain_id: Option<String>,

    /// The ID of the User the identity is mapped to.
    pub user_id: Option<String>,
}

pub enum SpiffeBindingFilter {
    Domain(String),
}

impl SpiffeBindingFilter {
    pub fn matches(&self, obj: &SpiffeBinding) -> bool {
        match self {
            SpiffeBindingFilter::Domain(val) => obj.domain_id == *val,
        }
    }
}

impl From<SpiffeBindingCreate> for SpiffeBinding {
    fn from(value: SpiffeBindingCreate) -> Self {
        Self {
            authorizations: value.authorizations,
            domain_id: value.domain_id,
            svid: value.svid,
            is_system: value.is_system,
            user_id: value.user_id,
        }
    }
}

impl SpiffeBinding {
    /// Apply the [`SpiffeBindingUpdate`] to the [`SpiffeBinding`] structure
    /// returning the new object.
    ///
    /// Construct a new version of the [`SpiffeBinding`] for persisting in the
    /// storage.
    pub fn with_update(self, update: SpiffeBindingUpdate) -> Self {
        Self {
            authorizations: update.authorizations,
            domain_id: self.domain_id,
            svid: self.svid,
            is_system: self.is_system,
            user_id: self.user_id,
        }
    }
}
