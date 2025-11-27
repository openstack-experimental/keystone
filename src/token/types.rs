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
//! Token provider types.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::assignment::types::Role;
use crate::identity::types::UserResponse;
use crate::resource::types::{Domain, Project};

pub mod application_credential;
pub mod domain_scoped;
pub mod federation_domain_scoped;
pub mod federation_project_scoped;
pub mod federation_unscoped;
pub mod project_scoped;
pub mod provider_api;
pub mod restricted;
pub mod unscoped;

pub use application_credential::ApplicationCredentialPayload;
pub use domain_scoped::{DomainScopePayload, DomainScopePayloadBuilder};
pub use federation_domain_scoped::{
    FederationDomainScopePayload, FederationDomainScopePayloadBuilder,
};
pub use federation_project_scoped::{
    FederationProjectScopePayload, FederationProjectScopePayloadBuilder,
};
pub use federation_unscoped::{FederationUnscopedPayload, FederationUnscopedPayloadBuilder};
pub use project_scoped::{ProjectScopePayload, ProjectScopePayloadBuilder};
pub use provider_api::TokenApi;
pub use restricted::*;
pub use unscoped::*;

/// Fernet Token.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Token {
    /// Unscoped.
    Unscoped(UnscopedPayload),
    /// Domain scoped.
    DomainScope(DomainScopePayload),
    /// Project scoped.
    ProjectScope(ProjectScopePayload),
    /// Federated unscoped.
    FederationUnscoped(FederationUnscopedPayload),
    /// Federated project scoped.
    FederationProjectScope(FederationProjectScopePayload),
    /// Federated domain scoped.
    FederationDomainScope(FederationDomainScopePayload),
    /// Application credential.
    ApplicationCredential(ApplicationCredentialPayload),
    /// Restricted.
    Restricted(RestrictedPayload),
}

impl Token {
    pub const fn user_id(&self) -> &String {
        match self {
            Self::Unscoped(x) => &x.user_id,
            Self::ProjectScope(x) => &x.user_id,
            Self::DomainScope(x) => &x.user_id,
            Self::FederationUnscoped(x) => &x.user_id,
            Self::FederationProjectScope(x) => &x.user_id,
            Self::FederationDomainScope(x) => &x.user_id,
            Self::ApplicationCredential(x) => &x.user_id,
            Self::Restricted(x) => &x.user_id,
        }
    }

    pub const fn user(&self) -> &Option<UserResponse> {
        match self {
            Self::Unscoped(x) => &x.user,
            Self::ProjectScope(x) => &x.user,
            Self::DomainScope(x) => &x.user,
            Self::FederationUnscoped(x) => &x.user,
            Self::FederationProjectScope(x) => &x.user,
            Self::FederationDomainScope(x) => &x.user,
            Self::ApplicationCredential(x) => &x.user,
            Self::Restricted(x) => &x.user,
        }
    }

    /// Set the `issued_at` property of the token.
    ///
    /// An internal method (available only within the module) to set the
    /// `issued_at` into the token payload.
    pub(super) fn set_issued_at(&mut self, issued_at: DateTime<Utc>) -> &mut Self {
        match self {
            Self::Unscoped(x) => x.issued_at = issued_at,
            Self::ProjectScope(x) => x.issued_at = issued_at,
            Self::DomainScope(x) => x.issued_at = issued_at,
            Self::FederationUnscoped(x) => x.issued_at = issued_at,
            Self::FederationProjectScope(x) => x.issued_at = issued_at,
            Self::FederationDomainScope(x) => x.issued_at = issued_at,
            Self::ApplicationCredential(x) => x.issued_at = issued_at,
            Self::Restricted(x) => x.issued_at = issued_at,
        }
        self
    }

    /// Get token `issued_at` timestamp.
    ///
    /// Returns the UTC timestamp when the token was encoded (part of the Fernet
    /// payload and not the token payload).
    pub const fn issued_at(&self) -> &DateTime<Utc> {
        match self {
            Self::Unscoped(x) => &x.issued_at,
            Self::ProjectScope(x) => &x.issued_at,
            Self::DomainScope(x) => &x.issued_at,
            Self::FederationUnscoped(x) => &x.issued_at,
            Self::FederationProjectScope(x) => &x.issued_at,
            Self::FederationDomainScope(x) => &x.issued_at,
            Self::ApplicationCredential(x) => &x.issued_at,
            Self::Restricted(x) => &x.issued_at,
        }
    }

    /// Get token expiration timestamp.
    pub const fn expires_at(&self) -> &DateTime<Utc> {
        match self {
            Self::Unscoped(x) => &x.expires_at,
            Self::ProjectScope(x) => &x.expires_at,
            Self::DomainScope(x) => &x.expires_at,
            Self::FederationUnscoped(x) => &x.expires_at,
            Self::FederationProjectScope(x) => &x.expires_at,
            Self::FederationDomainScope(x) => &x.expires_at,
            Self::ApplicationCredential(x) => &x.expires_at,
            Self::Restricted(x) => &x.expires_at,
        }
    }

    pub const fn methods(&self) -> &Vec<String> {
        match self {
            Self::Unscoped(x) => &x.methods,
            Self::ProjectScope(x) => &x.methods,
            Self::DomainScope(x) => &x.methods,
            Self::FederationUnscoped(x) => &x.methods,
            Self::FederationProjectScope(x) => &x.methods,
            Self::FederationDomainScope(x) => &x.methods,
            Self::ApplicationCredential(x) => &x.methods,
            Self::Restricted(x) => &x.methods,
        }
    }

    pub const fn audit_ids(&self) -> &Vec<String> {
        match self {
            Self::Unscoped(x) => &x.audit_ids,
            Self::ProjectScope(x) => &x.audit_ids,
            Self::DomainScope(x) => &x.audit_ids,
            Self::FederationUnscoped(x) => &x.audit_ids,
            Self::FederationProjectScope(x) => &x.audit_ids,
            Self::FederationDomainScope(x) => &x.audit_ids,
            Self::ApplicationCredential(x) => &x.audit_ids,
            Self::Restricted(x) => &x.audit_ids,
        }
    }

    pub const fn project(&self) -> Option<&Project> {
        match self {
            Self::ProjectScope(x) => x.project.as_ref(),
            Self::FederationProjectScope(x) => x.project.as_ref(),
            Self::Restricted(x) => x.project.as_ref(),
            _ => None,
        }
    }

    pub const fn project_id(&self) -> Option<&String> {
        match self {
            Self::ProjectScope(x) => Some(&x.project_id),
            Self::FederationProjectScope(x) => Some(&x.project_id),
            Self::Restricted(x) => Some(&x.project_id),
            _ => None,
        }
    }

    pub const fn domain(&self) -> Option<&Domain> {
        match self {
            Self::DomainScope(x) => x.domain.as_ref(),
            Self::FederationDomainScope(x) => x.domain.as_ref(),
            _ => None,
        }
    }

    pub const fn roles(&self) -> Option<&Vec<Role>> {
        match self {
            Self::DomainScope(x) => x.roles.as_ref(),
            Self::ProjectScope(x) => x.roles.as_ref(),
            Self::FederationProjectScope(x) => x.roles.as_ref(),
            Self::FederationDomainScope(x) => x.roles.as_ref(),
            Self::Restricted(x) => x.roles.as_ref(),
            _ => None,
        }
    }
}
