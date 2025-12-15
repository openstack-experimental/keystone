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
//! Keystone API types
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::{Validate, ValidationErrors};

use crate::catalog::types::{Endpoint as ProviderEndpoint, Service};
use crate::common::types as provider_types;
use crate::resource::types as resource_provider_types;

/// List of the supported API versionts as [Values].
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Versions {
    /// List of the versions.
    #[validate(nested)]
    pub versions: Values,
}

impl IntoResponse for Versions {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// A container with the [Version] list.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Values {
    #[validate(nested)]
    pub values: Vec<Version>,
}

/// Single API version container.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct SingleVersion {
    /// The version.
    #[validate(nested)]
    pub version: Version,
}

impl IntoResponse for SingleVersion {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// Single API version.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Version {
    /// Version id.
    #[validate(length(max = 5))]
    pub id: String,
    /// Version status.
    pub status: VersionStatus,
    /// Date of the version update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    /// Links to the API version.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub links: Option<Vec<Link>>,
    /// Supported media types.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub media_types: Option<Vec<MediaType>>,
}

/// Version status.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum VersionStatus {
    /// Stable.
    #[default]
    #[serde(rename = "stable")]
    Stable,
    /// Experimental.
    #[serde(rename = "experimental")]
    Experimental,
}

/// Link object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Link {
    /// Link rel attribute.
    #[validate(length(max = 10))]
    pub rel: String,
    /// link href attribute.
    #[validate(url)]
    pub href: String,
}

impl Link {
    pub fn new(href: String) -> Self {
        Self {
            rel: "self".into(),
            href,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct MediaType {
    pub base: String,
    pub r#type: String,
}

impl Default for MediaType {
    fn default() -> Self {
        Self {
            base: "application/json".into(),
            r#type: "application/vnd.openstack.identity-v3+json".into(),
        }
    }
}

/// A catalog object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Catalog(Vec<CatalogService>);

impl Validate for Catalog {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.0.validate()
    }
}

impl IntoResponse for Catalog {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// A catalog object.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(setter(strip_option, into))]
pub struct CatalogService {
    pub r#type: Option<String>,
    #[validate(length(max = 255))]
    pub name: Option<String>,
    #[validate(length(max = 64))]
    pub id: String,
    #[validate(nested)]
    pub endpoints: Vec<Endpoint>,
}

impl From<(Service, Vec<ProviderEndpoint>)> for CatalogService {
    fn from(value: (Service, Vec<ProviderEndpoint>)) -> Self {
        Self {
            id: value.0.id.clone(),
            name: value.0.name.clone(),
            r#type: value.0.r#type,
            endpoints: value.1.into_iter().map(Into::into).collect(),
        }
    }
}

/// A Catalog Endpoint.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(setter(strip_option, into))]
pub struct Endpoint {
    #[validate(length(max = 64))]
    pub id: String,
    #[validate(url)]
    pub url: String,
    #[validate(length(max = 64))]
    pub interface: String,
    #[builder(default)]
    #[validate(length(max = 64))]
    pub region: Option<String>,
    #[builder(default)]
    #[validate(length(max = 64))]
    pub region_id: Option<String>,
}

impl From<ProviderEndpoint> for Endpoint {
    fn from(value: ProviderEndpoint) -> Self {
        Self {
            id: value.id.clone(),
            interface: value.interface.clone(),
            url: value.url.clone(),
            region: value.region_id.clone(),
            region_id: value.region_id.clone(),
        }
    }
}

impl From<Vec<(Service, Vec<ProviderEndpoint>)>> for Catalog {
    fn from(value: Vec<(Service, Vec<ProviderEndpoint>)>) -> Self {
        Self(
            value
                .into_iter()
                .map(|(srv, eps)| (srv, eps).into())
                .collect(),
        )
    }
}

/// The authorization scope, including the system, a project, or a domain.
///
/// If multiple scopes are specified in the same request (e.g. project and
/// domain or domain and system) an HTTP 400 Bad Request will be returned, as a
/// token cannot be simultaneously scoped to multiple authorization targets. An
/// ID is sufficient to uniquely identify a project but if a project is
/// specified by name, then the domain of the project must also be specified in
/// order to uniquely identify the project by name. A domain scope may be
/// specified by either the domain’s ID or name with equivalent results.
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
#[builder(setter(into, strip_option))]
pub struct System {
    /// All systems access.
    #[builder(default)]
    pub all: Option<bool>,
}

impl From<resource_provider_types::Domain> for Domain {
    fn from(value: resource_provider_types::Domain) -> Self {
        Self {
            id: Some(value.id),
            name: Some(value.name),
        }
    }
}

impl From<&resource_provider_types::Domain> for Domain {
    fn from(value: &resource_provider_types::Domain) -> Self {
        Self {
            id: Some(value.id.clone()),
            name: Some(value.name.clone()),
        }
    }
}

/// Default `true` for the Deserialize trait.
pub(crate) fn default_true() -> bool {
    true
}

impl From<Domain> for provider_types::Domain {
    fn from(value: Domain) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<provider_types::Domain> for Domain {
    fn from(value: provider_types::Domain) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<ScopeProject> for provider_types::Project {
    fn from(value: ScopeProject) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain.map(Into::into),
        }
    }
}

impl From<provider_types::Project> for ScopeProject {
    fn from(value: provider_types::Project) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain.map(Into::into),
        }
    }
}

impl From<&provider_types::Project> for ScopeProject {
    fn from(value: &provider_types::Project) -> Self {
        Self::from(value.clone())
    }
}

impl From<System> for provider_types::System {
    fn from(value: System) -> Self {
        Self { all: value.all }
    }
}

impl From<Scope> for provider_types::Scope {
    fn from(value: Scope) -> Self {
        match value {
            Scope::Project(scope) => Self::Project(scope.into()),
            Scope::Domain(scope) => Self::Domain(scope.into()),
            Scope::System(scope) => Self::System(scope.into()),
        }
    }
}
