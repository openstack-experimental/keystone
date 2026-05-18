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
use openstack_keystone_core_types::auth::*;

use crate::api::KeystoneApiError;
use crate::auth::ValidatedSecurityContext;
use crate::identity::IdentityApi;
use crate::keystone::ServiceState;
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
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        #[cfg(any(test, feature = "mock"))]
        {
            if let Some(vsc) = parts.extensions.get::<ValidatedSecurityContext>() {
                vsc.fully_resolved()?;
                return Ok(Auth(vsc.clone()));
            }
        }

        if let Some(svid) = parts.extensions.get::<SpiffeId>() {
            tracing::debug!("spiffe svid present: {}", svid);
        }
        // Extract the interface on which the connection is being served
        let interface = parts
            .extensions
            .get::<Interface>()
            .cloned()
            .unwrap_or(Interface::Public);
        tracing::info!("the interface is {:?}", interface);

        let auth_header = parts
            .headers
            .get("X-Auth-Token")
            .and_then(|header| header.to_str().ok());

        let auth_header = if let Some(auth_header) = auth_header {
            auth_header
        } else {
            debug!("No supported information has been provided.");
            return Err(KeystoneApiError::UnauthorizedNoContext)?;
        };

        let state = Arc::from_ref(state);

        let mut auth_res = state
            .provider
            .get_token_provider()
            .authenticate_by_token(&state, auth_header, Some(false), None)
            .await
            .inspect_err(|e| error!("{:#?}", e))
            .map_err(|_| KeystoneApiError::UnauthorizedNoContext)?;

        if let IdentityInfo::User(ref mut identity) = auth_res.principal.identity {
            identity.user = Some(
                state
                    .provider
                    .get_identity_provider()
                    .get_user(&state, &identity.user_id)
                    .await
                    .map(|x| {
                        x.ok_or_else(|| KeystoneApiError::NotFound {
                            resource: "user".into(),
                            identifier: identity.user_id.clone(),
                        })
                    })??,
            );
        };
        let sc = SecurityContext::try_from(auth_res)?;
        let vsc = ValidatedSecurityContext::new_with_roles(sc, &state).await?;
        vsc.fully_resolved()?;

        Ok(Auth(vsc))
    }
}
