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
pub struct Project {
    /// The description of the project.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,

    /// The project domain_id.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled.
    pub enabled: bool,

    /// Additional project properties.
    #[builder(default)]
    pub extra: Option<Value>,

    /// The project ID.
    #[validate(length(min = 1, max = 255))]
    pub id: String,

    /// The project name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// The ID of the parent for the project.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub parent_id: Option<String>,
}

/// Project listing parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
pub struct ProjectListParameters {
    /// Filter project by the domain.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,

    /// Filter projects by the id attribute. Items are treated as `IN[]`.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub ids: Option<HashSet<String>>,

    /// Filter projects by the name attribute.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,
}
