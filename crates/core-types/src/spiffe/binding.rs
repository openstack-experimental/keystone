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
//! A binding represents a fixed bind between the SPIFFE identity and the OpenStack user and scope.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::{auth::AuthzInfo, error::BuilderError};

/// Spiffe identity binding.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct SpiffeBinding {
    /// Bound authorizations.
    /// TODO: the authorization should also contain of role filters (limiting the highest possible
    /// role to be used by identity).
    pub authorizations: Option<Vec<AuthzInfo>>,

    /// SPIFFE SVID.
    pub spiffe_id: String,

    /// Flag indicating the system wide identity (system scope)
    pub is_system: bool,

    /// The ID of the User the identity is mapped to.
    pub user_id: String,
}

/// New binding.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct SpiffeBindingCreate {
    /// Bound authorizations.
    pub authorizations: Option<Vec<AuthzInfo>>,

    /// SPIFFE SVID.
    pub spiffe_id: String,

    /// Flag indicating the system wide identity (system scope). This property cannot be changed.
    /// System bindings are also protected from deletion.
    pub is_system: bool,

    /// The ID of the User the identity is mapped to.
    pub user_id: String,
}

/// Update Spiffe binding.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct SpiffeBindingUpdate {
    /// Bound authorizations.
    pub authorizations: Option<Vec<AuthzInfo>>,
}

/// K8s Auth role list parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
pub struct SpiffeBindingListParameters {
    /// The ID of the User the identity is mapped to.
    pub user_id: Option<String>,
}

impl From<SpiffeBindingCreate> for SpiffeBinding {
    fn from(value: SpiffeBindingCreate) -> Self {
        Self {
            authorizations: value.authorizations,
            spiffe_id: value.spiffe_id,
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
            spiffe_id: self.spiffe_id,
            is_system: self.is_system,
            user_id: self.user_id,
        }
    }
}
