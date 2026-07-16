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

use crate::credential::CredentialProviderError;
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

    /// Domain not found.
    #[error("domain {0} not found")]
    DomainNotFound(String),

    /// Invalid `domain_id`/`is_domain`/`parent_id` combination on project
    /// create (e.g. `domain_id` set while `is_domain` is true, or `domain_id`
    /// not matching the parent project's domain).
    #[error("invalid project domain: {0}")]
    InvalidProjectDomain(String),

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
