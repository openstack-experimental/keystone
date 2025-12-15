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
//! # Common types
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use validator::Validate;

/// The authorization scope, including the system, a project, or a domain.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Project scope.
    Project(Project),
    /// Domain scope.
    Domain(Domain),
    /// System scope.
    System(System),
}

/// Project scope information
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
pub struct Project {
    /// Project ID.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,
    /// Project Name.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub name: Option<String>,
    /// Domain the project belongs to.
    #[builder(default)]
    pub domain: Option<Domain>,
}

/// Domain scope information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(into))]
pub struct Domain {
    /// Domain ID.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,
    /// Domain Name.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub name: Option<String>,
}

/// System scope information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(into))]
pub struct System {
    /// All systems scope.
    #[builder(default)]
    pub all: Option<bool>,
}

impl Validate for Scope {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Self::Project(x) => x.validate(),
            Self::Domain(x) => x.validate(),
            Self::System(x) => x.validate(),
        }
    }
}
