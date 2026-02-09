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
use serde_json::Value;
use std::collections::HashSet;
use validator::Validate;

use crate::error::BuilderError;

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Domain {
    /// The resource description.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,

    /// If set to true, domain is enabled. If set to false, domain is disabled.
    pub enabled: bool,

    /// The domain ID.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The domain name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// Additional domain properties.
    #[builder(default)]
    pub extra: Option<Value>,
}

/// Domain listing parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
pub struct DomainListParameters {
    /// Filter domains by the `id` attribute. Items are treated as `IN[]`.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub ids: Option<HashSet<String>>,

    /// Filter domains by the `name` attribute.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,
}
