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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::catalog::types::{Endpoint as ProviderEndpoint, Service};
use crate::resource::types as resource_provider_types;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Versions {
    pub versions: Values,
}

impl IntoResponse for Versions {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Values {
    pub values: Vec<Version>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct SingleVersion {
    pub version: Version,
}

impl IntoResponse for SingleVersion {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Version {
    pub id: String,
    pub status: VersionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_types: Option<Vec<MediaType>>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum VersionStatus {
    #[default]
    #[serde(rename = "stable")]
    Stable,
    #[serde(rename = "experimental")]
    Experimental,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Link {
    pub rel: String,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
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

impl IntoResponse for Catalog {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// A catalog object.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct CatalogService {
    pub r#type: Option<String>,
    pub name: Option<String>,
    pub id: String,
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
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct Endpoint {
    pub id: String,
    pub url: String,
    pub interface: String,
    #[builder(default)]
    pub region: Option<String>,
    #[builder(default)]
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
    Project(ProjectScope),
    /// Domain scope.
    Domain(Domain),
    /// System scope.
    System(System),
}

/// Project scope information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(into, strip_option))]
pub struct ProjectScope {
    /// Project ID.
    #[builder(default)]
    pub id: Option<String>,
    /// Project Name.
    #[builder(default)]
    pub name: Option<String>,
    /// Project domain.
    #[builder(default)]
    pub domain: Option<Domain>,
}

/// Domain information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(into, strip_option))]
pub struct Domain {
    /// Domain ID.
    #[builder(default)]
    pub id: Option<String>,
    /// Domain Name.
    #[builder(default)]
    pub name: Option<String>,
}

/// Project information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Project {
    /// Project ID.
    pub id: String,
    /// Project Name.
    pub name: String,
    /// project domain.
    pub domain: Domain,
}

/// System scope.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(into, strip_option))]
pub struct System {
    /// All systems access.
    #[builder(default)]
    pub all: Option<bool>,
}

impl From<resource_provider_types::Domain> for Domain {
    fn from(value: resource_provider_types::Domain) -> Self {
        Self {
            id: Some(value.id.clone()),
            name: Some(value.name.clone()),
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
