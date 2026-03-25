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
//! Token provider errors.

use thiserror::Error;

use crate::application_credential::ApplicationCredentialProviderError;
use crate::assignment::AssignmentProviderError;
use crate::auth::AuthenticationError;
use crate::error::BuilderError;
use crate::identity::IdentityProviderError;
use crate::resource::ResourceProviderError;
use crate::revoke::RevokeProviderError;
use crate::role::RoleProviderError;
use crate::trust::TrustProviderError;

/// Token provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TokenProviderError {
    /// Actor has no roles on the target scope.
    #[error("actor has no roles on scope")]
    ActorHasNoRolesOnTarget,

    /// Application Credential has expired.
    #[error("application credential has expired")]
    ApplicationCredentialExpired,

    /// Application Credential used in the token is not found.
    #[error("application credential with id: {0} not found")]
    ApplicationCredentialNotFound(String),

    /// Application credential provider error.
    #[error(transparent)]
    ApplicationCredentialProvider {
        /// The source of the error.
        #[from]
        source: ApplicationCredentialProviderError,
    },

    /// Application Credential is bound to the other project.
    #[error("application credential is bound to another project")]
    ApplicationCredentialScopeMismatch,

    /// Assignment provider error.
    #[error(transparent)]
    AssignmentProvider {
        /// The source of the error.
        #[from]
        source: AssignmentProviderError,
    },

    /// Authentication error.
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),

    /// Conflict.
    #[error("{message}")]
    Conflict { message: String, context: String },

    /// The domain is disabled.
    #[error("domain is disabled")]
    DomainDisabled(String),

    /// Driver error.
    #[error("backend driver error: {source}")]
    Driver {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Expired token.
    #[error("token expired")]
    Expired,

    /// Expiry calculation error.
    #[error("token expiry calculation failed")]
    ExpiryCalculation,

    /// Federated payload missing data error.
    #[error("federated payload must contain idp_id and protocol_id")]
    FederatedPayloadMissingData,

    /// Identity provider error.
    #[error(transparent)]
    IdentityProvider(#[from] IdentityProviderError),

    /// The project is disabled.
    #[error("project disabled")]
    ProjectDisabled(String),

    /// Resource provider error.
    #[error(transparent)]
    ResourceProvider(#[from] ResourceProviderError),

    /// Restricted token project scoped error.
    #[error("token with restrictions can be only project scoped")]
    RestrictedTokenNotProjectScoped,

    /// Revoke Provider error.
    #[error(transparent)]
    RevokeProvider(#[from] RevokeProviderError),

    /// Role provider error.
    #[error(transparent)]
    RoleProvider {
        /// The source of the error.
        #[from]
        source: RoleProviderError,
    },

    /// Target scope information is not found in the token.
    #[error("scope information missing")]
    ScopeMissing,

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder(#[from] BuilderError),

    /// Target subject information is not found in the token.
    #[error("subject information missing")]
    SubjectMissing,

    /// Token restriction not found error.
    #[error("token restriction {0} not found")]
    TokenRestrictionNotFound(String),

    /// Revoked token error.
    #[error("token has been revoked")]
    TokenRevoked,

    /// Trust provider error.
    #[error(transparent)]
    TrustProvider(#[from] TrustProviderError),

    /// The user domain of the trustee is disabled.
    #[error("trustee domain disabled")]
    TrustorDomainDisabled,

    /// Unsupported token restriction driver.
    #[error("driver `{0}` is not supported for the token provider")]
    UnsupportedDriver(String),

    /// Unsupported token restriction driver.
    #[error("driver `{0}` is not supported for the token restriction provider")]
    UnsupportedTRDriver(String),

    /// The user is disabled.
    #[error("user disabled")]
    UserDisabled(String),

    /// The user domain is disabled.
    #[error("user domain disabled")]
    UserDomainDisabled,

    /// The user is not trustee.
    #[error("the token subject user is not trustee of the trust")]
    UserIsNotTrustee,

    /// The user cannot be found error.
    #[error("user cannot be found: {0}")]
    UserNotFound(String),

    /// UUID decryption error.
    #[error("uuid decryption error")]
    Uuid(#[from] uuid::Error),

    /// Validation error.
    #[error("Token validation error: {0}")]
    Validation(#[from] validator::ValidationErrors),
}
