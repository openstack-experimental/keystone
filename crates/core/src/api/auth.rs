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
//! # API authentication handling
use std::ops::Deref;
use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use spiffe::SpiffeId;
use tracing::{debug, error};

use openstack_keystone_config::Interface;
use openstack_keystone_core_types::{auth::*, spiffe::SpiffeBindingBuilder};

use crate::api::KeystoneApiError;
use crate::auth::ValidatedSecurityContext;
use crate::keystone::ServiceState;
use crate::spiffe::SpiffeApi;
use crate::token::TokenApi;

#[derive(Debug, Clone)]
pub struct Auth(pub ValidatedSecurityContext);

impl Deref for Auth {
    type Target = ValidatedSecurityContext;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for Auth
where
    ServiceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = KeystoneApiError;

    #[tracing::instrument(skip(state), err)]
    /// Try to authenticate the request
    ///
    /// Authenticate the request creating the `ValidatedSecurityContext` using
    /// the following information:
    ///
    /// * `mTLS` - SPIFFE issued x509 certificate that is passed as an extension
    ///   by the mtls
    /// connection handler. For the SVID a corresponding binding is looked up.
    /// When present the `ValidatedSecurityContext` is attempted to be
    /// instantiated as `ScopeInfo::Unscoped` scope.
    /// * `X-Auth-Token` - HTTP header is used as encoded `FernetToken` which is
    ///   decoded and used
    /// to instantiate the `ValidatedSecurityContext`. The `FernetToken` always
    /// contains the scope information (whether it is scoped or explicitly
    /// Unscoped).
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Only available in tests - get mock ValidatedSecurityContext injected as
        // extension instead of populating mocks for all individual calls.
        #[cfg(any(test, feature = "mock"))]
        {
            if let Some(vsc) = parts.extensions.get::<ValidatedSecurityContext>() {
                vsc.fully_resolved()?;
                return Ok(Auth(vsc.clone()));
            }
        }

        // Extract the interface on which the connection is being served
        // TODO: Insert interface info into the Context
        let interface = parts
            .extensions
            .get::<Interface>()
            .cloned()
            .unwrap_or(Interface::Public);

        let state = Arc::from_ref(state);

        // Check the SPIFFE svid first as the primary identity source
        if let Some(svid) = parts.extensions.get::<SpiffeId>() {
            tracing::debug!("authenticating the spiffe svid {}", svid);

            if let Some(admin_svid) = &state
                .config_manager
                .config
                .read()
                .await
                .interface_admin
                .as_ref()
                .and_then(|admin_if| admin_if.admin_svid.as_ref())
                && interface == Interface::Admin
            {
                // The admin_svid was configured and it is it over the admin interface - short
                // circuit the admin
                let auth_result: AuthenticationResult = AuthenticationResultBuilder::default()
                    .context(AuthenticationContext::Spiffe(
                        SpiffeBindingBuilder::default()
                            .svid(*admin_svid)
                            .domain_id("")
                            .is_system(true)
                            .build()?,
                    ))
                    .principal(
                        PrincipalInfoBuilder::default()
                            .identity(IdentityInfo::Principal(
                                PrincipalIdentityInfoBuilder::default()
                                    .id(*admin_svid)
                                    .issuer(svid.trust_domain_name())
                                    .build()?,
                            ))
                            .build()?,
                    )
                    .build()?;

                let mut ctx = SecurityContext::try_from(auth_result)?;
                ctx.set_is_admin();
                let vsc = ValidatedSecurityContext::new_for_scope(
                    ctx,
                    ScopeInfo::System("all".into()),
                    &state,
                )
                .await?;
                return Ok(Auth(vsc));
            }
            if let Some(binding) = state
                .provider
                .get_spiffe_provider()
                .get_binding(&state, &svid.to_string())
                .await?
            {
                let auth_result: AuthenticationResult = AuthenticationResultBuilder::default()
                    .context(AuthenticationContext::Spiffe(binding.clone()))
                    .principal(
                        PrincipalInfoBuilder::default()
                            .identity(IdentityInfo::Principal(
                                PrincipalIdentityInfoBuilder::default()
                                    .id(binding.svid.clone())
                                    .issuer(svid.trust_domain_name())
                                    .build()?,
                            ))
                            .build()?,
                    )
                    .build()?;
                let ctx = SecurityContext::try_from(auth_result)?;
                let vsc = ValidatedSecurityContext::new_for_scope(
                    ctx,
                    if binding.is_system {
                        // For the "system" binding explicitly scope as system
                        ScopeInfo::System("all".into())
                    } else {
                        ScopeInfo::Unscoped
                    },
                    &state,
                )
                .await?;
                return Ok(Auth(vsc));
            } else {
                tracing::debug!("no binding for the svid present: {}", svid);
            }
        }
        // Now headers can be checked
        if let Some(auth_header) = parts
            .headers
            .get("X-Auth-Token")
            .and_then(|header| header.to_str().ok())
        {
            tracing::debug!("authenticating request with the x-auth-token");
            let vsc = state
                .provider
                .get_token_provider()
                .authorize_by_token(&state, auth_header, Some(false), None)
                .await
                .inspect_err(|e| error!("{:#?}", e))
                .map_err(|_| KeystoneApiError::UnauthorizedNoContext)?;

            vsc.fully_resolved()?;
            return Ok(Auth(vsc));
        }

        debug!("No supported information has been provided.");
        Err(KeystoneApiError::UnauthorizedNoContext)
    }
}
