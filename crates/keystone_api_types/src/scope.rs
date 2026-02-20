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
//! # Keystone Scope API types
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::{Validate, ValidationErrors};

use crate::error::BuilderError;

/// The authorization scope, including the system, a project, or a domain.
///
/// If multiple scopes are specified in the same request (e.g. project and
/// domain or domain and system) an HTTP 400 Bad Request will be returned, as a
/// token cannot be simultaneously scoped to multiple authorization targets. An
/// ID is sufficient to uniquely identify a project but if a project is
/// specified by name, then the domain of the project must also be specified in
/// order to uniquely identify the project by name. A domain scope may be
/// specified by either the domain's ID or name with equivalent results.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Project scope.
    Project(ScopeProject),
    /// Domain scope.
    Domain(Domain),
    /// System scope.
    System(System),
}

impl Validate for Scope {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Self::Project(project) => project.validate(),
            Self::Domain(domain) => domain.validate(),
            Self::System(system) => system.validate(),
        }
    }
}

/// Project scope information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct ScopeProject {
    /// Project ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub id: Option<String>,
    /// Project Name.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub name: Option<String>,
    /// Project domain.
    #[builder(default)]
    pub domain: Option<Domain>,
}

/// Domain information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct Domain {
    /// Domain ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub id: Option<String>,
    /// Domain Name.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub name: Option<String>,
}

/// Project information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
pub struct Project {
    /// Project ID.
    #[validate(length(max = 64))]
    pub id: String,
    /// Project Name.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub name: String,
    /// project domain.
    pub domain: Domain,
}

/// System scope.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct System {
    /// All systems access.
    #[builder(default)]
    pub all: Option<bool>,
}
