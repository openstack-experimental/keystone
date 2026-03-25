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

use chrono::Utc;

pub use openstack_keystone_core_types::token::*;

use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
use crate::resource::ResourceApi;
use crate::token::error::TokenProviderError;
use crate::trust::TrustApi;

/// Validate the token scope.
///
/// Validate the scope validity of the token scope. For a project scoped
/// tokens this will raise an error when the project is disabled. For
/// domain scoped token the domain must be active.
pub async fn validate_token_scope(
    token: &Token,
    _state: &ServiceState,
) -> Result<(), TokenProviderError> {
    match token {
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
        Token::SystemScope(_data) => {}
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

/// Validate the token subject.
///
/// Perform checks for the token subject:
///
/// - user is enabled
/// - user domain is enabled
/// - application credential is not expired
pub async fn validate_token_subject(
    token: &Token,
    state: &ServiceState,
) -> Result<(), TokenProviderError> {
    let user_domain_id: String;
    if let Some(user) = token.user() {
        // The "user" must be active
        if !user.enabled {
            return Err(TokenProviderError::UserDisabled(user.id.clone()));
        }

        // Ensure user domain is enabled
        if !state
            .provider
            .get_resource_provider()
            .get_domain_enabled(state, &user.domain_id)
            .await?
        {
            return Err(TokenProviderError::UserDomainDisabled);
        }

        user_domain_id = user.domain_id.clone();
    } else {
        return Err(TokenProviderError::SubjectMissing);
    }

    match token {
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
        Token::SystemScope(_data) => {}
        Token::Trust(data) => {
            // Validate the trust chain
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
            // Validate trustor and trustee
            if let Some(trust) = &data.trust {
                if data.user_id != trust.trustee_user_id {
                    return Err(TokenProviderError::UserIsNotTrustee);
                }

                // Resolve and verify trustor domain is enabled
                let trustor_domain_id = state
                    .provider
                    .get_identity_provider()
                    .get_user_domain_id(state, &trust.trustor_user_id)
                    .await?;

                if user_domain_id != trustor_domain_id
                    && !state
                        .provider
                        .get_resource_provider()
                        .get_domain_enabled(state, &trustor_domain_id)
                        .await?
                {
                    return Err(TokenProviderError::TrustorDomainDisabled);
                }
            } else {
                return Err(TokenProviderError::SubjectMissing);
            }
        }
        Token::Unscoped(_data) => {}
    }
    Ok(())
}
