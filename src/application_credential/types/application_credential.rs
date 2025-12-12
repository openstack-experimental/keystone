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
//! # Application credential types

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use validator::Validate;

use super::{AccessRule, AccessRuleCreate};
use crate::assignment::types::Role;
use crate::error::BuilderError;

/// The application credential object.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(strip_option, into))]
#[builder(build_fn(error = "BuilderError"))]
pub struct ApplicationCredential {
    /// A list of access_rules objects.
    #[builder(default)]
    #[validate(nested)]
    pub access_rules: Option<Vec<AccessRule>>,

    /// The actor id.
    #[builder(default)]
    pub description: Option<String>,

    /// The expiration time of the application credential, if one was specified.
    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,

    /// The ID of the application credential.
    #[validate(length(max = 64))]
    pub id: String,

    /// The name of the application credential.
    #[validate(length(max = 255))]
    pub name: String,

    /// The ID of the project the application credential was created for and
    /// that authentication requests using this application credential will
    /// be scoped to.
    #[validate(length(max = 64))]
    pub project_id: String,

    /// A list of one or more roles that this application credential has
    /// associated with its project. A token using this application
    /// credential will have these same roles.
    #[validate(nested)]
    pub roles: Vec<Role>,

    /// A flag indicating whether the application credential may be used for
    /// creation or destruction of other application credentials or trusts.
    pub unrestricted: bool,

    /// The ID of the user who owns the application credential.
    #[validate(length(max = 64))]
    pub user_id: String,
}

/// The created application credential object.
#[derive(Builder, Clone, Debug, Deserialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ApplicationCredentialCreateResponse {
    /// A list of access_rules objects.
    #[builder(default)]
    #[validate(nested)]
    pub access_rules: Option<Vec<AccessRule>>,

    /// The actor id.
    #[builder(default)]
    pub description: Option<String>,

    /// The expiration time of the application credential, if one was specified.
    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,

    /// The ID of the application credential.
    #[validate(length(max = 64))]
    pub id: String,

    /// The name of the application credential.
    #[validate(length(max = 255))]
    pub name: String,

    /// The ID of the project the application credential was created for and
    /// that authentication requests using this application credential will
    /// be scoped to.
    #[validate(length(max = 64))]
    pub project_id: String,

    /// A list of one or more roles that this application credential has
    /// associated with its project. A token using this application
    /// credential will have these same roles.
    #[builder(default)]
    #[validate(nested)]
    pub roles: Vec<Role>,

    /// The secret that the application credential was be created with. This is
    /// only ever shown once in the response to a create request. It is not
    /// stored nor ever shown again. If the secret is lost, a new application
    /// credential must be created.
    pub secret: SecretString,

    /// A flag indicating whether the application credential may be used for
    /// creation or destruction of other application credentials or trusts.
    pub unrestricted: bool,

    /// The ID of the user who owns the application credential.
    #[validate(length(max = 64))]
    pub user_id: String,
}

/// The application credential object to be created.
#[derive(Builder, Clone, Debug, Default, Deserialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ApplicationCredentialCreate {
    /// A list of access_rules objects.
    #[builder(default)]
    #[validate(nested)]
    pub access_rules: Option<Vec<AccessRuleCreate>>,

    /// The actor id.
    #[builder(default)]
    pub description: Option<String>,

    /// The expiration time of the application credential, if one was specified.
    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,

    /// The ID of the application credential.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The name of the application credential.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// The ID of the project the application credential was created for and
    /// that authentication requests using this application credential will
    /// be scoped to.
    #[validate(length(max = 64))]
    pub project_id: String,

    /// A list of one or more roles that this application credential has
    /// associated with its project. A token using this application
    /// credential will have these same roles.
    #[validate(nested)]
    pub roles: Vec<Role>,

    /// The secret that the application credential will be created with. If not
    /// provided, one will be generated.
    #[builder(default)]
    pub secret: Option<SecretString>,

    /// A flag indicating whether the application credential may be used for
    /// creation or destruction of other application credentials or trusts.
    /// Defaults to false.
    #[builder(default)]
    pub unrestricted: Option<bool>,

    /// The ID of the user who owns the application credential.
    #[validate(length(max = 64))]
    pub user_id: String,
}

/// Parameters for listing application credentials.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ApplicationCredentialListParameters {
    /// Limit number of entries on the single response page.
    #[builder(default)]
    pub limit: Option<u64>,

    /// Page marker (id of the last entry on the previous page).
    #[builder(default)]
    pub marker: Option<String>,

    /// Filter application credentials by the name attribute.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// The ID of the user owning the application credential.
    #[validate(length(max = 64))]
    pub user_id: String,
}

impl From<ApplicationCredentialCreateResponse> for ApplicationCredential {
    fn from(value: ApplicationCredentialCreateResponse) -> Self {
        Self {
            access_rules: value.access_rules,
            description: value.description,
            expires_at: value.expires_at,
            id: value.id,
            name: value.name,
            project_id: value.project_id,
            roles: value.roles,
            unrestricted: value.unrestricted,
            user_id: value.user_id,
        }
    }
}
