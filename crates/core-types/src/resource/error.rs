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

use thiserror::Error;

use crate::application_credential::ApplicationCredentialProviderError;
use crate::assignment::AssignmentProviderError;
use crate::credential::CredentialProviderError;
use crate::identity::IdentityProviderError;
use crate::idmapping::IdMappingProviderError;
use crate::oauth2_key::Oauth2KeyProviderError;

#[derive(Error, Debug)]
pub enum ResourceProviderError {
    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Credential provider error, surfaced when cascading a project
    /// deletion into `delete_credentials_for_project` (ADR 0019 §3).
    #[error(transparent)]
    CredentialProvider {
        #[from]
        source: CredentialProviderError,
    },

    /// Application credential provider error, surfaced when cascading a
    /// project deletion into `delete_application_credentials_for_project`.
    #[error(transparent)]
    ApplicationCredentialProvider {
        /// Boxed: the error types are recursive.
        source: Box<ApplicationCredentialProviderError>,
    },

    /// Assignment provider error, surfaced when cascading a project deletion
    /// into the revocation of its role assignments.
    #[error(transparent)]
    AssignmentProvider {
        /// Boxed: the assignment error embeds this one.
        source: Box<AssignmentProviderError>,
    },

    /// Identity provider error, surfaced when cascading a domain deletion
    /// into the deletion of its users and groups.
    #[error(transparent)]
    IdentityProvider {
        /// Boxed: the identity error embeds this one.
        source: Box<IdentityProviderError>,
    },

    /// Id-mapping provider error, surfaced when cascading a domain deletion
    /// into `delete_mappings_for_domain`.
    #[error(transparent)]
    IdMappingProvider {
        #[from]
        source: IdMappingProviderError,
    },

    /// Domain not found.
    #[error("domain {0} not found")]
    DomainNotFound(String),

    /// Invalid `domain_id`/`is_domain`/`parent_id` combination on project
    /// create (e.g. `domain_id` set while `is_domain` is true, or `domain_id`
    /// not matching the parent project's domain).
    #[error("invalid project domain: {0}")]
    InvalidProjectDomain(String),

    /// The resource has `options.immutable == true` and the requested update
    /// does not itself clear that flag, or the request is a delete (which can
    /// never clear it). Mirrors Python Keystone's `ResourceUpdateForbidden` /
    /// `ResourceDeleteForbidden`.
    #[error("resource {0} is immutable")]
    Immutable(String),

    /// The domain is enabled and still owns projects, users or groups, so
    /// deleting it would delete them as well. Disable the domain first (the
    /// same precondition Python Keystone enforces for any domain delete).
    #[error("domain {0} is enabled and not empty, disable it before deleting it")]
    DomainEnabled(String),

    /// OAuth2 signing key provider error, surfaced when provisioning a
    /// domain's initial signing keypair synchronously on domain creation
    /// (ADR 0026 §3, "Domain creation").
    #[error(transparent)]
    Oauth2KeyProvider {
        #[from]
        source: Oauth2KeyProviderError,
    },

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

    /// (De)Ser error.
    #[error(transparent)]
    Serde {
        /// The source of the error.
        #[from]
        source: serde_json::Error,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: crate::error::BuilderError,
    },

    /// Project not found.
    #[error("project {0} not found")]
    ProjectNotFound(String),

    /// Project tag not found.
    #[error("tag {tag} of the project {project_id} not found")]
    ProjectTagNotFound {
        /// The project ID.
        project_id: String,
        /// The tag.
        tag: String,
    },

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the resource provider")]
    UnsupportedDriver(String),

    /// Request validation error.
    #[error("request validation error: {}", source)]
    Validation {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },
}

impl From<ApplicationCredentialProviderError> for ResourceProviderError {
    fn from(source: ApplicationCredentialProviderError) -> Self {
        Self::ApplicationCredentialProvider {
            source: Box::new(source),
        }
    }
}

impl From<AssignmentProviderError> for ResourceProviderError {
    fn from(source: AssignmentProviderError) -> Self {
        Self::AssignmentProvider {
            source: Box::new(source),
        }
    }
}

impl From<IdentityProviderError> for ResourceProviderError {
    fn from(source: IdentityProviderError) -> Self {
        Self::IdentityProvider {
            source: Box::new(source),
        }
    }
}
