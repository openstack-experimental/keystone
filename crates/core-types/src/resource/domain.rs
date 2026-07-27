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

use std::collections::{HashMap, HashSet};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

use crate::error::BuilderError;
use crate::resource::project::ProjectOptions;

/// Domain data.
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
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,

    /// The resource options for the domain. A domain is a project row with
    /// `is_domain = true` and shares the `project_option` table, hence the
    /// shared [`ProjectOptions`](crate::resource::ProjectOptions) type.
    #[builder(default)]
    #[validate(nested)]
    pub options: ProjectOptions,
}

/// New domain data.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct DomainCreate {
    /// The resource description.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,

    /// If set to true, domain is enabled. If set to false, domain is disabled.
    #[builder(default = "crate::default_true()")]
    pub enabled: bool,

    /// The domain ID.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The domain name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// Additional domain properties.
    #[builder(default)]
    pub extra: HashMap<String, Value>,

    /// The resource options for the domain.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<ProjectOptions>,
}

/// Domain update data.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct DomainUpdate {
    /// New description. `None` = unchanged, `Some(None)` = clear.
    #[builder(default)]
    pub description: Option<Option<String>>,

    /// New enabled state. `None` = unchanged.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// New name. `None` = unchanged.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,

    /// Additional domain properties. The provider merges this into the
    /// existing `extra` before persisting; an empty map means unchanged.
    #[builder(default)]
    pub extra: HashMap<String, Value>,

    /// The resource options for the domain. `None` means unchanged; a field
    /// left `None` within `Some(ProjectOptions { .. })` also means unchanged.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<ProjectOptions>,
}

/// Domain listing parameters.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
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

    /// Pagination controls (limit/marker/page_reverse).
    #[builder(default)]
    pub pagination: crate::ListPagination,
}
