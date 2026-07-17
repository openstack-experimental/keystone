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
//! # LDAP bind authentication (ADR-0027 §3)
//!
//! Two-step flow: resolve the caller's user DN via the service pool, bind
//! as that DN with the supplied password via the dedicated auth pool, then
//! re-fetch the user's attributes via the service pool to build the
//! [`AuthenticationResult`].
use openstack_keystone_config::LdapProvider;
use openstack_keystone_core::auth::{
    AuthenticationContext, AuthenticationError, AuthenticationResult, AuthenticationResultBuilder,
    IdentityInfo, PrincipalInfo, UserIdentityInfoBuilder,
};
use openstack_keystone_core_types::identity::{IdentityProviderError, UserPasswordAuthRequest};

use crate::connection::{AuthPool, ServicePool};
use crate::user;

/// Authenticate a user by password against the directory.
///
/// `auth.id` selects the user directly; `auth.name` (with `auth.domain`)
/// resolves by name first. A domain other than the configured default can
/// never match an LDAP user (ADR-0027 §11), and is rejected the same way an
/// unknown user is, to avoid distinguishing "wrong domain" from "wrong
/// user" in the response.
pub async fn authenticate_by_password(
    service_pool: &ServicePool,
    auth_pool: &AuthPool,
    cfg: &LdapProvider,
    default_domain_id: &str,
    auth: &UserPasswordAuthRequest,
) -> Result<AuthenticationResult, IdentityProviderError> {
    if let Some(domain_id) = auth.domain.as_ref().and_then(|d| d.id.as_deref())
        && domain_id != default_domain_id
    {
        return Err(AuthenticationError::UserNameOrPasswordWrong.into());
    }

    let user_dn = user::resolve_dn(service_pool, cfg, auth.id.as_deref(), auth.name.as_deref())
        .await?
        .ok_or(AuthenticationError::UserNameOrPasswordWrong)?;

    auth_pool
        .try_bind(&user_dn, &auth.password)
        .await
        .map_err(|_| AuthenticationError::UserNameOrPasswordWrong)?;

    let user_response = user::get_by_dn(service_pool, cfg, default_domain_id, &user_dn)
        .await?
        .ok_or(AuthenticationError::UserNameOrPasswordWrong)?;

    if !user_response.enabled {
        return Err(AuthenticationError::UserDisabled(user_response.id).into());
    }

    Ok(AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_response.id.clone())
                    .user(user_response)
                    .build()?,
            ),
        })
        .build()?)
}
