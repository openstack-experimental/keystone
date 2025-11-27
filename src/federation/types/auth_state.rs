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

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::api::types::{
    Domain as ApiDomain, ProjectScope as ApiProjectScope, Scope as ApiScope, System as ApiSystem,
};

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct AuthState {
    /// IDP ID
    pub idp_id: String,

    /// Mapping ID
    pub mapping_id: String,

    /// Auth state (Primary key, CSRF)
    pub state: String,

    /// Nonce
    pub nonce: String,

    /// Requested redirect uri
    pub redirect_uri: String,

    /// PKCE verifier value
    pub pkce_verifier: String,

    /// Timestamp when the auth will expire
    #[builder(default)]
    pub expires_at: DateTime<Utc>,

    /// Requested scope
    #[builder(default)]
    pub scope: Option<Scope>,
}

//#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
//#[serde(rename_all = "lowercase")]
//pub enum Scope {
//    Project(String),
//    Domain(String),
//    System(String),
//}
/// The authorization scope, including the system (Since v3.10), a project, or a
/// domain (Since v3.4). If multiple scopes are specified in the same request
/// (e.g. project and domain or domain and system) an HTTP 400 Bad Request will
/// be returned, as a token cannot be simultaneously scoped to multiple
/// authorization targets. An ID is sufficient to uniquely identify a project
/// but if a project is specified by name, then the domain of the project must
/// also be specified in order to uniquely identify the project by name. A
/// domain scope may be specified by either the domain’s ID or name with
/// equivalent results.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Project scope
    Project(Project),
    /// Domain scope
    Domain(Domain),
    /// System scope
    System(System),
}

/// Project scope information
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Project {
    /// Project ID
    pub id: Option<String>,
    /// Project Name
    pub name: Option<String>,
    /// project domain
    pub domain: Option<Domain>,
}

/// Domain information
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(into))]
pub struct Domain {
    /// Domain ID
    #[builder(default)]
    pub id: Option<String>,
    /// Domain Name
    #[builder(default)]
    pub name: Option<String>,
}

/// System scope
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(into))]
pub struct System {
    /// system scope
    #[builder(default)]
    pub all: Option<bool>,
}

impl From<ApiDomain> for Domain {
    fn from(value: ApiDomain) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<Domain> for ApiDomain {
    fn from(value: Domain) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<ApiProjectScope> for Project {
    fn from(value: ApiProjectScope) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain.map(Into::into),
        }
    }
}

impl From<Project> for ApiProjectScope {
    fn from(value: Project) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain.map(Into::into),
        }
    }
}

impl From<&Project> for ApiProjectScope {
    fn from(value: &Project) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            domain: value.domain.clone().map(Into::into),
        }
    }
}

impl From<ApiSystem> for System {
    fn from(value: ApiSystem) -> Self {
        Self { all: value.all }
    }
}

impl From<ApiScope> for Scope {
    fn from(value: ApiScope) -> Self {
        match value {
            ApiScope::Project(scope) => Scope::Project(scope.into()),
            ApiScope::Domain(scope) => Scope::Domain(scope.into()),
            ApiScope::System(scope) => Scope::System(scope.into()),
        }
    }
}
