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

use crate::error::BuilderError;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

/// Role representation.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Role {
    /// The role ID.
    #[validate(length(min = 1, max = 64))]
    pub id: String,
    /// The role name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    /// The role domain_id.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,
    /// The role description.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,
    /// Additional role properties.
    #[builder(default)]
    pub extra: Option<Value>,
}

/// Query parameters for listing roles.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RoleListParameters {
    /// Filter roles by the domain.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,
    /// Filter roles by the name attribute.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
}

/// Role creation data.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RoleCreate {
    /// The role ID.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,
    /// The role name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    /// The role domain_id.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,
    /// The role description.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub description: Option<String>,
    /// Additional role properties.
    #[builder(default)]
    pub extra: Option<Value>,
}
