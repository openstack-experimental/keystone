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
use validator::Validate;

use crate::assignment::types::Role;
use crate::identity::types::UserResponse;
use crate::keystone::ServiceState;
use crate::resource::types::{Domain, Project};
use crate::token::error::TokenProviderError;
use crate::trust::TrustApi;

pub mod application_credential;
pub mod common;
pub mod domain_scoped;
pub mod federation_domain_scoped;
pub mod federation_project_scoped;
pub mod federation_unscoped;
pub mod project_scoped;
pub mod provider_api;
pub mod restricted;
pub mod trust;
pub mod unscoped;

pub use application_credential::*;
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
pub use trust::*;
pub use unscoped::*;

/// Fernet Token.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Token {
    /// Application credential.
    ApplicationCredential(ApplicationCredentialPayload),
    /// Domain scoped.
    DomainScope(DomainScopePayload),
    /// Federated domain scoped.
    FederationDomainScope(FederationDomainScopePayload),
    /// Federated project scoped.
    FederationProjectScope(FederationProjectScopePayload),
    /// Federated unscoped.
    FederationUnscoped(FederationUnscopedPayload),
    /// Project scoped.
    ProjectScope(ProjectScopePayload),
    /// Restricted.
    Restricted(RestrictedPayload),
    /// Trust.
    Trust(TrustPayload),
    /// Unscoped.
    Unscoped(UnscopedPayload),
}

impl Token {
    pub const fn user_id(&self) -> &String {
        match self {
            Self::ApplicationCredential(x) => &x.user_id,
            Self::DomainScope(x) => &x.user_id,
            Self::FederationUnscoped(x) => &x.user_id,
            Self::FederationProjectScope(x) => &x.user_id,
            Self::FederationDomainScope(x) => &x.user_id,
            Self::ProjectScope(x) => &x.user_id,
            Self::Restricted(x) => &x.user_id,
            Self::Trust(x) => &x.user_id,
            Self::Unscoped(x) => &x.user_id,
        }
    }

    pub const fn user(&self) -> &Option<UserResponse> {
        match self {
            Self::ApplicationCredential(x) => &x.user,
            Self::DomainScope(x) => &x.user,
            Self::FederationUnscoped(x) => &x.user,
            Self::FederationProjectScope(x) => &x.user,
            Self::FederationDomainScope(x) => &x.user,
            Self::ProjectScope(x) => &x.user,
            Self::Restricted(x) => &x.user,
            Self::Trust(x) => &x.user,
            Self::Unscoped(x) => &x.user,
        }
    }

    /// Set the `issued_at` property of the token.
    ///
    /// An internal method (available only within the module) to set the
    /// `issued_at` into the token payload.
    pub(super) fn set_issued_at(&mut self, issued_at: DateTime<Utc>) -> &mut Self {
        match self {
            Self::ApplicationCredential(x) => x.issued_at = issued_at,
            Self::DomainScope(x) => x.issued_at = issued_at,
            Self::FederationUnscoped(x) => x.issued_at = issued_at,
            Self::FederationProjectScope(x) => x.issued_at = issued_at,
            Self::FederationDomainScope(x) => x.issued_at = issued_at,
            Self::ProjectScope(x) => x.issued_at = issued_at,
            Self::Restricted(x) => x.issued_at = issued_at,
            Self::Trust(x) => x.issued_at = issued_at,
            Self::Unscoped(x) => x.issued_at = issued_at,
        }
        self
    }

    /// Get token `issued_at` timestamp.
    ///
    /// Returns the UTC timestamp when the token was encoded (part of the Fernet
    /// payload and not the token payload).
    pub const fn issued_at(&self) -> &DateTime<Utc> {
        match self {
            Self::ApplicationCredential(x) => &x.issued_at,
            Self::DomainScope(x) => &x.issued_at,
            Self::FederationUnscoped(x) => &x.issued_at,
            Self::FederationProjectScope(x) => &x.issued_at,
            Self::FederationDomainScope(x) => &x.issued_at,
            Self::ProjectScope(x) => &x.issued_at,
            Self::Restricted(x) => &x.issued_at,
            Self::Trust(x) => &x.issued_at,
            Self::Unscoped(x) => &x.issued_at,
        }
    }

    /// Get token expiration timestamp.
    pub const fn expires_at(&self) -> &DateTime<Utc> {
        match self {
            Self::ApplicationCredential(x) => &x.expires_at,
            Self::DomainScope(x) => &x.expires_at,
            Self::FederationUnscoped(x) => &x.expires_at,
            Self::FederationProjectScope(x) => &x.expires_at,
            Self::FederationDomainScope(x) => &x.expires_at,
            Self::ProjectScope(x) => &x.expires_at,
            Self::Restricted(x) => &x.expires_at,
            Self::Trust(x) => &x.expires_at,
            Self::Unscoped(x) => &x.expires_at,
        }
    }

    pub const fn methods(&self) -> &Vec<String> {
        match self {
            Self::ApplicationCredential(x) => &x.methods,
            Self::DomainScope(x) => &x.methods,
            Self::FederationUnscoped(x) => &x.methods,
            Self::FederationProjectScope(x) => &x.methods,
            Self::FederationDomainScope(x) => &x.methods,
            Self::ProjectScope(x) => &x.methods,
            Self::Restricted(x) => &x.methods,
            Self::Trust(x) => &x.methods,
            Self::Unscoped(x) => &x.methods,
        }
    }

    pub const fn audit_ids(&self) -> &Vec<String> {
        match self {
            Self::ApplicationCredential(x) => &x.audit_ids,
            Self::DomainScope(x) => &x.audit_ids,
            Self::FederationUnscoped(x) => &x.audit_ids,
            Self::FederationProjectScope(x) => &x.audit_ids,
            Self::FederationDomainScope(x) => &x.audit_ids,
            Self::ProjectScope(x) => &x.audit_ids,
            Self::Restricted(x) => &x.audit_ids,
            Self::Trust(x) => &x.audit_ids,
            Self::Unscoped(x) => &x.audit_ids,
        }
    }

    pub const fn project(&self) -> Option<&Project> {
        match self {
            Self::ApplicationCredential(x) => x.project.as_ref(),
            Self::ProjectScope(x) => x.project.as_ref(),
            Self::FederationProjectScope(x) => x.project.as_ref(),
            Self::Restricted(x) => x.project.as_ref(),
            Self::Trust(x) => x.project.as_ref(),
            _ => None,
        }
    }

    pub const fn project_id(&self) -> Option<&String> {
        match self {
            Self::ApplicationCredential(x) => Some(&x.project_id),
            Self::FederationProjectScope(x) => Some(&x.project_id),
            Self::ProjectScope(x) => Some(&x.project_id),
            Self::Restricted(x) => Some(&x.project_id),
            Self::Trust(x) => Some(&x.project_id),
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
            Self::ApplicationCredential(x) => match &x.application_credential {
                Some(ac) => Some(&ac.roles),
                None => None,
            },
            Self::DomainScope(x) => x.roles.as_ref(),
            Self::FederationProjectScope(x) => x.roles.as_ref(),
            Self::FederationDomainScope(x) => x.roles.as_ref(),
            Self::ProjectScope(x) => x.roles.as_ref(),
            Self::Restricted(x) => x.roles.as_ref(),
            Self::Trust(x) => match &x.trust {
                Some(trust) => trust.roles.as_ref(),
                None => None,
            },
            _ => None,
        }
    }

    /// Validate the token scope.
    ///
    /// Validate the scope validity of the token scope. For a project scoped
    /// tokens this will raise an error when the project is disabled. For
    /// domain scoped token the domain must be active.
    pub async fn validate_scope(&self, _state: &ServiceState) -> Result<(), TokenProviderError> {
        match self {
            Token::ApplicationCredential(data) => {
                if !data
                    .project
                    .as_ref()
                    .ok_or(TokenProviderError::ScopeMissing)?
                    .enabled
                {
                    return Err(TokenProviderError::ProjectDisabled(data.project_id.clone()));
                }
                if data
                    .application_credential
                    .as_ref()
                    .is_none_or(|ac| ac.project_id != data.project_id)
                {
                    return Err(TokenProviderError::ApplicationCredentialScopeMismatch);
                }
            }
            Token::DomainScope(data) => {
                if !data
                    .domain
                    .as_ref()
                    .ok_or(TokenProviderError::ScopeMissing)?
                    .enabled
                {
                    return Err(TokenProviderError::DomainDisabled(data.domain_id.clone()));
                }
            }
            Token::FederationDomainScope(data) => {
                if !data
                    .domain
                    .as_ref()
                    .ok_or(TokenProviderError::ScopeMissing)?
                    .enabled
                {
                    return Err(TokenProviderError::DomainDisabled(data.domain_id.clone()));
                }
            }
            Token::FederationProjectScope(data) => {
                if !data
                    .project
                    .as_ref()
                    .ok_or(TokenProviderError::ScopeMissing)?
                    .enabled
                {
                    return Err(TokenProviderError::ProjectDisabled(data.project_id.clone()));
                }
            }
            Token::FederationUnscoped(_) => {}
            Token::ProjectScope(data) => {
                if !data
                    .project
                    .as_ref()
                    .ok_or(TokenProviderError::ScopeMissing)?
                    .enabled
                {
                    return Err(TokenProviderError::ProjectDisabled(data.project_id.clone()));
                }
            }
            Token::Restricted(data) => {
                if !data
                    .project
                    .as_ref()
                    .ok_or(TokenProviderError::ScopeMissing)?
                    .enabled
                {
                    return Err(TokenProviderError::ProjectDisabled(data.project_id.clone()));
                }
            }
            Token::Trust(data) => {
                if !data
                    .project
                    .as_ref()
                    .ok_or(TokenProviderError::ScopeMissing)?
                    .enabled
                {
                    return Err(TokenProviderError::ProjectDisabled(data.project_id.clone()));
                }
            }
            Token::Unscoped(_) => {}
        }
        Ok(())
    }

    /// Validate the token issuer.
    ///
    /// Perform checks for the token subject:
    ///
    /// - user is enabled
    /// - user domain is enabled
    /// - application credential is not expired
    pub async fn validate_subject(&self, state: &ServiceState) -> Result<(), TokenProviderError> {
        // The "user" must be active
        if !self.user().as_ref().is_some_and(|user| user.enabled) {
            return Err(TokenProviderError::UserDisabled(self.user_id().clone()));
        }
        // TODO: User domain must be enabled

        match self {
            Token::ApplicationCredential(data) => {
                // Check whether application credential is expired
                if data
                    .application_credential
                    .as_ref()
                    .and_then(|ac| ac.expires_at)
                    .is_some_and(|expiry| expiry < Utc::now())
                {
                    return Err(TokenProviderError::Expired);
                }
            }
            Token::DomainScope(_data) => {}
            Token::FederationDomainScope(_data) => {}
            Token::FederationProjectScope(_data) => {}
            Token::FederationUnscoped(_data) => {}
            Token::ProjectScope(_data) => {}
            Token::Restricted(_data) => {}
            Token::Trust(data) => {
                state
                    .provider
                    .get_trust_provider()
                    .validate_trust_delegation_chain(
                        state,
                        data.trust
                            .as_ref()
                            .ok_or(TokenProviderError::SubjectMissing)?,
                    )
                    .await?;
            }
            Token::Unscoped(_data) => {}
        }
        Ok(())
    }
}

impl Validate for Token {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Self::ApplicationCredential(x) => x.validate(),
            Self::DomainScope(x) => x.validate(),
            Self::FederationUnscoped(x) => x.validate(),
            Self::FederationProjectScope(x) => x.validate(),
            Self::FederationDomainScope(x) => x.validate(),
            Self::ProjectScope(x) => x.validate(),
            Self::Restricted(x) => x.validate(),
            Self::Trust(x) => x.validate(),
            Self::Unscoped(x) => x.validate(),
        }
    }
}
