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
//! Shared handling of the user reference (user ID, or user name + domain)
//! supplied by the credential based authentication requests.
//!
//! This only normalizes the reference. It performs no enabled checks: the
//! user and domain state is enforced by the backend drivers and, as the
//! final gate, by `SecurityContext::validate`.

use openstack_keystone_core_types::identity::{Domain, UserResponse};

use crate::auth::ExecutionContext;
use crate::identity::IdentityProviderError;
use crate::resource::error::ResourceProviderError;

/// Normalize the user reference so that it is resolvable by the backends.
///
/// When the user ID is not given, the name and the domain are required and
/// the domain name (if given) is resolved into the domain ID. A reference
/// carrying the user ID is left untouched.
///
/// # Errors
/// - [`IdentityProviderError::UserIdOrNameWithDomain`] when neither the ID, nor
///   the name together with the domain is given.
/// - [`ResourceProviderError::DomainNotFound`] when the domain name does not
///   exist.
pub(crate) async fn resolve_user_domain<'a>(
    ctx: &ExecutionContext<'a>,
    id: Option<&str>,
    name: Option<&str>,
    domain: &mut Option<Domain>,
) -> Result<(), IdentityProviderError> {
    if id.is_some() {
        return Ok(());
    }
    if name.is_none() {
        return Err(IdentityProviderError::UserIdOrNameWithDomain);
    }
    let Some(domain) = domain else {
        return Err(IdentityProviderError::UserIdOrNameWithDomain);
    };
    if let Some(dname) = &domain.name {
        let d = ctx
            .state()
            .provider
            .get_resource_provider()
            .find_domain_by_name(ctx, dname)
            .await?
            .ok_or(ResourceProviderError::DomainNotFound(dname.clone()))?;
        domain.id = Some(d.id);
    } else if domain.id.is_none() {
        return Err(IdentityProviderError::UserIdOrNameWithDomain);
    }
    Ok(())
}

/// Check that the optional name and domain of the user reference match the
/// resolved user.
///
/// The user ID takes precedence for the lookup, but when the caller supplied
/// the name and/or the domain in addition they must describe the same user.
/// Every authentication method applies this check consistently, after the
/// user is resolved by ID. Returns `false` on any mismatch (including a
/// non-existing domain); the caller maps it to its uniform failure.
pub(crate) async fn user_matches_ref<'a>(
    ctx: &ExecutionContext<'a>,
    user: &UserResponse,
    name: Option<&str>,
    domain: Option<&Domain>,
) -> Result<bool, IdentityProviderError> {
    if name.is_some_and(|name| name != user.name) {
        return Ok(false);
    }
    let Some(domain) = domain else {
        return Ok(true);
    };
    if domain.id.as_ref().is_some_and(|did| *did != user.domain_id) {
        return Ok(false);
    }
    if let Some(domain_name) = &domain.name {
        let user_domain = ctx
            .state()
            .provider
            .get_resource_provider()
            .get_domain(ctx, &user.domain_id)
            .await?;
        if user_domain.is_none_or(|d| d.name != *domain_name) {
            return Ok(false);
        }
    }
    Ok(true)
}
