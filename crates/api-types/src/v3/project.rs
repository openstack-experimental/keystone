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

use crate::{Link, ResourceLinks};
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
    //#[serde(skip_serializing_if = "Option::is_none")]
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

    /// Links of the project.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<ResourceLinks>,

    /// Indicates whether the project also acts as a domain. If set to true,
    /// this project acts as both a project and domain. As a domain, the project
    /// provides a name space in which you can create users, groups, and other
    /// projects. If set to false, this project behaves as a regular project
    /// that contains only resources.
    pub is_domain: bool,

    /// The name of the project.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,

    /// The resource options for the project. Available resource options are
    /// documented in `ProjectOptions`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub options: Option<ProjectOptions>,

    /// The ID of the parent for the project. Serialized as `null` when the
    /// project has no parent.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default)]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub parent_id: Option<String>,

    /// The tags of the project.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Project resource options.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
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
pub struct ProjectOptions {
    /// When `true`, the project cannot be updated or deleted until an
    /// administrator explicitly sets this back to `false`. Also used for
    /// domains, which persist through the same underlying project.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immutable: Option<bool>,
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
    ///
    /// If not specified, the domain is resolved from `parent_id`'s domain,
    /// or falls back to the domain the caller's token is scoped to.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled. The defaults is `true`.
    #[cfg_attr(feature = "builder", builder(default = "crate::default_true()"))]
    #[serde(default = "crate::default_true")]
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
    #[serde(default)]
    pub is_domain: bool,

    /// The name of the project, which must be unique within the owning domain.
    /// A project can have the same name as its domain.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub name: String,

    /// The resource options for the project. Available resource options are
    /// documented in `ProjectOptions`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub options: Option<ProjectOptions>,

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

    /// The tags of the project. A tag must be 1 to 255 characters long, must
    /// not contain `/` or `,` and a project can have up to 80 tags.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[cfg(feature = "builder")]
impl ProjectCreateBuilder {
    fn validate(&self) -> Result<(), String> {
        if self.parent_id.is_some() && self.is_domain.is_some_and(|x| x) {
            return Err("project cannot specify `parent_id` when `is_domain` is true".to_string());
        }
        if self.domain_id.as_ref().is_some_and(|x| x.is_some()) && self.is_domain.is_some_and(|x| x)
        {
            return Err("project cannot specify `domain_id` when `is_domain` is true".to_string());
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

/// Parameters controlling the hierarchy data returned together with a single
/// project.
///
/// Every flag is considered set when the query parameter is present (with an
/// empty value or any value other than `false` or `0`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ProjectShowParameters {
    /// Return the list of the project parents (from the closest to the root).
    /// Mutually exclusive with `parents_as_ids`.
    pub parents_as_list: Option<String>,

    /// Return the parents of the project as a nested object of the project
    /// IDs. Mutually exclusive with `parents_as_list`.
    pub parents_as_ids: Option<String>,

    /// Return the list of all project descendants. Mutually exclusive with
    /// `subtree_as_ids`.
    pub subtree_as_list: Option<String>,

    /// Return the descendants of the project as a nested object of the
    /// project IDs. Mutually exclusive with `subtree_as_list`.
    pub subtree_as_ids: Option<String>,
}

/// Single entry of the project hierarchy list.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProjectHierarchyItem {
    /// Project object.
    pub project: Project,
}

/// Project relatives (parents or subtree).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum ProjectHierarchy {
    /// Flat list of the projects.
    List(Vec<ProjectHierarchyItem>),

    /// Nested object of the project IDs where leaves are `null`.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    Ids(serde_json::Value),
}

/// Project with the optional hierarchy information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProjectWithHierarchy {
    /// Project attributes.
    #[serde(flatten)]
    pub project: Project,

    /// Parents of the project when requested with `parents_as_list` or
    /// `parents_as_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parents: Option<ProjectHierarchy>,

    /// Descendants of the project when requested with `subtree_as_list` or
    /// `subtree_as_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtree: Option<ProjectHierarchy>,
}

/// Single project response with the optional hierarchy information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProjectHierarchyResponse {
    /// Project object.
    pub project: ProjectWithHierarchy,
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

/// Update project data.
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
pub struct ProjectUpdate {
    /// The description of the project.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub description: Option<String>,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled.
    #[cfg_attr(feature = "builder", builder(default))]
    pub enabled: Option<bool>,

    /// Additional project properties.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,

    /// The project name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub name: Option<String>,

    /// The resource options for the project. Available resource options are
    /// documented in `ProjectOptions`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub options: Option<ProjectOptions>,

    /// The new set of tags replacing the existing ones. Omit to keep the
    /// tags unchanged.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Project update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectUpdateRequest {
    /// Project object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub project: ProjectUpdate,
}

/// List of projects.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectShortList {
    /// Collection of project objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub projects: Vec<ProjectShort>,

    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

/// List of full projects.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectList {
    /// Collection of project objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub projects: Vec<Project>,

    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

/// Project tags.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProjectTags {
    /// The list of tags.
    pub tags: Vec<String>,
}

/// Project list parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ProjectListParameters {
    /// Filter projects by domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,

    /// Filter projects by the `id` attribute.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub ids: Option<String>,

    /// Filter projects by name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,

    /// Filter projects by the `enabled` flag.
    #[serde(default, deserialize_with = "crate::deserialize_lenient_bool_opt")]
    pub enabled: Option<bool>,

    /// Comma-separated tags. Return only projects carrying all of them.
    #[cfg_attr(
        feature = "validate",
        validate(custom(function = "validate_tag_filter"))
    )]
    pub tags: Option<String>,

    /// Comma-separated tags. Return only projects carrying at least one of
    /// them.
    #[serde(rename = "tags-any")]
    #[cfg_attr(
        feature = "validate",
        validate(custom(function = "validate_tag_filter"))
    )]
    pub tags_any: Option<String>,

    /// Comma-separated tags. Exclude projects carrying all of them.
    #[serde(rename = "not-tags")]
    #[cfg_attr(
        feature = "validate",
        validate(custom(function = "validate_tag_filter"))
    )]
    pub not_tags: Option<String>,

    /// Comma-separated tags. Exclude projects carrying at least one of them.
    #[serde(rename = "not-tags-any")]
    #[cfg_attr(
        feature = "validate",
        validate(custom(function = "validate_tag_filter"))
    )]
    pub not_tags_any: Option<String>,
}

/// Maximum number of tags in one tag filter. Matches the number of tags a
/// project can carry; each item adds a sub-query to the list query.
#[cfg(feature = "validate")]
const MAX_TAG_FILTER_ITEMS: usize = 80;

/// Validate a comma-separated tag filter: at most [`MAX_TAG_FILTER_ITEMS`]
/// items, each 1 to 255 characters long.
#[cfg(feature = "validate")]
fn validate_tag_filter(value: &str) -> Result<(), validator::ValidationError> {
    let mut count = 0;
    for tag in value.split(',') {
        count += 1;
        if count > MAX_TAG_FILTER_ITEMS || !(1..=255).contains(&tag.chars().count()) {
            return Err(validator::ValidationError::new("tag_filter"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "builder")]
    use super::*;
    #[cfg(feature = "builder")]
    use crate::error::BuilderError;

    #[cfg(feature = "validate")]
    #[test]
    fn test_validate_tag_filter() {
        use super::validate_tag_filter;
        assert!(validate_tag_filter("a").is_ok());
        assert!(validate_tag_filter("a,b").is_ok());
        assert!(validate_tag_filter("").is_err());
        assert!(validate_tag_filter("a,,b").is_err());
        assert!(validate_tag_filter(&"a".repeat(256)).is_err());
        let ok = (0..80).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        assert!(validate_tag_filter(&ok).is_ok());
        let too_many = (0..81).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        assert!(validate_tag_filter(&too_many).is_err());
    }

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

        let sot_no_domain = ProjectCreateBuilder::default()
            .name("name")
            .build()
            .unwrap();
        assert!(sot_no_domain.domain_id.is_none(), "domain_id is optional");

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

        if let Err(BuilderError::Validation(..)) = ProjectCreateBuilder::default()
            .name("name")
            .domain_id("did")
            .is_domain(true)
            .build()
        {
        } else {
            panic!(
                "an error should be raised not allowing to set domain_id with the is_domain=true"
            );
        }
    }

    #[cfg(feature = "builder")]
    #[test]
    fn test_project_serialize_extra() {
        assert_eq!(
            serde_json::json!({"name": "name", "domain_id": "did", "enabled": true, "is_domain": false}),
            serde_json::to_value(
                ProjectCreateBuilder::default()
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
                ProjectCreateBuilder::default()
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

    #[cfg(feature = "validate")]
    #[test]
    fn test_project_name_length() {
        use validator::Validate;
        let ok = "a".repeat(64);
        let long = "a".repeat(65);

        let req: super::ProjectCreateRequest =
            serde_json::from_value(serde_json::json!({"project": {"name": ok}})).unwrap();
        assert!(req.validate().is_ok());
        let req: super::ProjectCreateRequest =
            serde_json::from_value(serde_json::json!({"project": {"name": long}})).unwrap();
        assert!(req.validate().is_err(), "create rejects name > 64");

        let req: super::ProjectUpdateRequest =
            serde_json::from_value(serde_json::json!({"project": {"name": ok}})).unwrap();
        assert!(req.validate().is_ok());
        let req: super::ProjectUpdateRequest =
            serde_json::from_value(serde_json::json!({"project": {"name": long}})).unwrap();
        assert!(req.validate().is_err(), "update rejects name > 64");
    }
}
