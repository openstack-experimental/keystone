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
//! Project API types.

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// Short Project representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectShort {
    /// The ID of the domain for the project.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled.
    pub enabled: bool,

    /// The ID for the project.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// The name of the project.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,
}

/// Full project representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Project {
    /// The description of the project.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub description: Option<String>,

    /// The ID of the domain for the project.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled.
    pub enabled: bool,

    /// Additional project properties.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    //#[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,

    /// The ID for the project.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// Indicates whether the project also acts as a domain. If set to true,
    /// this project acts as both a project and domain. As a domain, the project
    /// provides a name space in which you can create users, groups, and other
    /// projects. If set to false, this project behaves as a regular project
    /// that contains only resources.
    pub is_domain: bool,

    /// The name of the project.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,

    /// The ID of the parent for the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub parent_id: Option<String>,
}

/// New project data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError", validate = "Self::validate"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectCreate {
    /// The description of the project.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The ID of the domain for the project.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled. The defaults is `true`.
    #[cfg_attr(feature = "builder", builder(default = "crate::default_true()"))]
    pub enabled: bool,

    /// Additional project properties.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    //pub extra: ExtraFields,
    pub extra: std::collections::HashMap<String, serde_json::Value>,

    /// Indicates whether the project also acts as a domain. If set to true,
    /// this project acts as both a project and domain. As a domain, the project
    /// provides a name space in which you can create users, groups, and other
    /// projects. If set to false, this project behaves as a regular project
    /// that contains only resources. Default is false. You cannot update this
    /// parameter after you create the project.
    #[cfg_attr(feature = "builder", builder(default))]
    pub is_domain: bool,

    /// The name of the project, which must be unique within the owning domain.
    /// A project can have the same name as its domain.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,

    // TODO: add options
    /// The ID of the parent of the project.
    ///
    /// If specified on project creation, this places the project within a
    /// hierarchy and implicitly defines the owning domain, which will be the
    /// same domain as the parent specified. If `parent_id` is not specified and
    /// `is_domain` is false, then the project will use its owning domain as its
    /// parent. If `is_domain` is true (i.e. the project is acting as a domain),
    /// then `parent_id` must not specified (or if it is, it must be null) since
    /// domains have no parents.
    ///
    /// `parent_id` is immutable, and can’t be updated after the project is
    /// created - hence a project cannot be moved within the hierarchy.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

#[cfg(feature = "builder")]
impl ProjectCreateBuilder {
    fn validate(&self) -> Result<(), String> {
        if self.parent_id.is_some() && self.is_domain.is_some_and(|x| x) {
            return Err("project cannot specify `parent_id` when `is_domain` is true".to_string());
        }
        Ok(())
    }
}

/// Complete response with the project data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectResponse {
    /// Project object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub project: Project,
}

/// New project creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectCreateRequest {
    /// Project object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub project: ProjectCreate,
}

/// List of projects.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectShortList {
    /// Collection of project objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub projects: Vec<ProjectShort>,
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "builder")]
    use super::*;
    #[cfg(feature = "builder")]
    use crate::error::BuilderError;

    #[cfg(feature = "builder")]
    #[test]
    fn test_project_create() {
        let sot = ProjectCreateBuilder::default()
            .name("name")
            .domain_id("did")
            .build()
            .unwrap();
        assert!(sot.enabled, "enabled defaults to true");
        assert!(!sot.is_domain, "is_domain defaults to false");
        assert!(sot.parent_id.is_none());
        if let Err(BuilderError::Validation(..)) = ProjectCreateBuilder::default()
            .name("name")
            .domain_id("did")
            .enabled(true)
            .is_domain(true)
            .parent_id("foo")
            .build()
        {
        } else {
            panic!(
                "an error should be raised not allowing to set parent_id with the is_domain=true"
            );
        }
    }

    #[cfg(feature = "builder")]
    #[test]
    fn test_project_serialize_extra() {
        assert_eq!(
            serde_json::json!({"name": "name", "domain_id": "did", "enabled": true, "is_domain": false}),
            serde_json::to_value(
                &ProjectCreateBuilder::default()
                    .name("name")
                    .domain_id("did")
                    .build()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            serde_json::json!({"name": "name", "domain_id": "did", "enabled": true, "is_domain": false, "unknown": "bar"}),
            serde_json::to_value(
                &ProjectCreateBuilder::default()
                    .name("name")
                    .domain_id("did")
                    .extra(std::collections::HashMap::from([(
                        "unknown".into(),
                        serde_json::json!("bar")
                    )]))
                    .build()
                    .unwrap()
            )
            .unwrap()
        );
    }
}
