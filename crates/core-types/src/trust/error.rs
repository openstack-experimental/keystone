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
//! # Trust Error
use thiserror::Error;

use crate::assignment::AssignmentProviderError;
use crate::auth::AuthenticationError;
use crate::error::BuilderError;
use crate::revoke::RevokeProviderError;
use crate::role::RoleProviderError;

/// Trust extension error.
#[derive(Error, Debug)]
pub enum TrustProviderError {
    /// Assignment provider error.
    #[error(transparent)]
    AssignmentProvider {
        /// The source of the error.
        #[from]
        source: AssignmentProviderError,
    },

    /// Supported authentication error.
    #[error(transparent)]
    AuthenticationInfo {
        /// The source of the error.
        #[from]
        source: AuthenticationError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

    /// Trust expiration is more than the redelegated trust can provide.
    #[error("requested expiration is more than the redelegated trust can provide")]
    ExpirationImpossible,

    /// DateTime parsing error.
    #[error("error parsing int column as datetime: {expires_at}")]
    ExpirationDateTimeParse { id: String, expires_at: i64 },

    /// Relegated trust does not allow impersonation.
    #[error(
        "impersonation is not allowed because redelegated trust does not specify impersonation"
    )]
    RedelegatedImpersonationNotAllowed,

    /// Relegation trust must not add new roles.
    #[error("some of the requested roles are not in the redelegated trust")]
    RedelegatedRolesNotAvailable,

    /// `project_id` and `roles` must both be set or both be unset.
    #[error("project_id and roles must both be set, or both be unset")]
    ProjectRolesPairingInvalid,

    /// Redelegation chain is longer than allowed.
    #[error("redelegation depth of {length} is out of allowed range [0..{max_depth}]")]
    RedelegationDeepnessExceed { length: usize, max_depth: usize },

    /// Remaining uses of the trust is exceeded.
    #[error("remaining uses exceed")]
    RemainingUsesExceed,

    /// Remaining uses must be unset to redelegate a trust.
    #[error("remaining uses is set while it must not be set in order to redelegate a trust")]
    RemainingUsesMustBeUnset,

    /// The trustor does not currently hold one of the requested roles on the
    /// target project.
    #[error("trustor does not hold role `{role_id}` on the target project")]
    RoleNotGranted {
        /// The ID of the role that is not currently granted to the trustor.
        role_id: String,
    },

    /// Revoke provider error.
    #[error(transparent)]
    RevokeProvider {
        /// The source of the error.
        #[from]
        source: RevokeProviderError,
    },

    /// Role provider error.
    #[error(transparent)]
    RoleProvider {
        /// The source of the error.
        #[from]
        source: RoleProviderError,
    },

    /// (de)serialization error.
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
        source: BuilderError,
    },

    /// Trust used in the token is not found.
    #[error("trust with id: {0} not found")]
    TrustNotFound(String),

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the trust provider")]
    UnsupportedDriver(String),
}
