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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::BuilderError;

/// Service account representation.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ServiceAccount {
    /// The ID of the domain.
    #[validate(length(max = 64))]
    pub domain_id: String,

    /// If the service account is enabled, this value is true. Otherwise,
    /// this value is false.
    pub enabled: bool,

    /// The resource options for the user.
    /// The user ID.
    #[validate(length(max = 64))]
    pub id: String,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    pub name: String,
}

/// Service account creation data.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ServiceAccountCreate {
    /// The ID of the domain.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// If the service account is enabled, this value is true.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// The ID of the service account. When unset a new UUID would be assigned.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The service account name. Must be unique within the owning domain.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
}

/// The service account update object.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct ServiceAccountUpdate {
    /// Enable or disable the service account.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    #[builder(default)]
    pub name: Option<String>,
}

/// Service account listing parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
pub struct ServiceAccountListParameters {
    /// Filter service accounts by the domain.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,

    /// Filter users by the name attribute.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,
}
