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

use axum::{
    Json, debug_handler,
    extract::{Path, State},
    response::IntoResponse,
};
use chrono::{Local, TimeDelta};
use std::collections::HashSet;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
};

use crate::api::error::KeystoneApiError;
use crate::api::v4::federation::error::OidcError;
use crate::api::v4::federation::types::*;
use crate::federation::FederationApi;
use crate::federation::types::{AuthState, MappingListParameters as ProviderMappingListParameters};
use crate::keystone::ServiceState;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(post))
}

/// Authenticate using identity provider.
///
/// Initiate the authentication for the given identity provider. Mapping can be
/// passed, otherwise the one which is set as a default on the identity provider
/// level is used.
///
/// The API returns the link to the identity provider which must be open in the
/// web browser. Once user authenticates in the identity provider UI a redirect
/// to the url passed as a callback in the request is being done as a typical
/// oauth2 authorization code callback. The client is responsible for serving
/// this callback server and use received authorization code and state to
/// exchange it for the Keystone token passing it to the
/// `/v4/federation/oidc/callback`.
///
/// Desired scope (OpenStack) can be also passed to get immediately scoped token
/// after the authentication completes instead of the unscoped token.
///
/// This is an unauthenticated API call. User, mapping, scope validation will
/// happen when the callback is invoked.
#[utoipa::path(
    post,
    path = "/identity_providers/{idp_id}/auth",
    operation_id = "federation/identity_provider/auth:post",
    request_body = IdentityProviderAuthRequest,
    responses(
        (status = CREATED, description = "Authentication data", body = IdentityProviderAuthResponse),
    ),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_auth",
    level = "debug",
    skip(state),
    err(Debug)
)]
#[debug_handler]
pub async fn post(
    State(state): State<ServiceState>,
    Path(idp_id): Path<String>,
    Json(req): Json<IdentityProviderAuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    state
        .config
        .auth
        .methods
        .iter()
        .find(|m| *m == "openid")
        .ok_or(KeystoneApiError::AuthMethodNotSupported)?;

    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id,
            })
        })??;

    let mapping = if let Some(mapping_id) = req.mapping_id {
        state
            .provider
            .get_federation_provider()
            .get_mapping(&state, &mapping_id)
            .await
            .map(|x| {
                x.ok_or_else(|| KeystoneApiError::NotFound {
                    resource: "mapping".into(),
                    identifier: mapping_id.clone(),
                })
            })??
    } else if let Some(mapping_name) = req.mapping_name.or(idp.default_mapping_name) {
        state
            .provider
            .get_federation_provider()
            .list_mappings(
                &state,
                &ProviderMappingListParameters {
                    idp_id: Some(idp.id.clone()),
                    name: Some(mapping_name.clone()),
                    ..Default::default()
                },
            )
            .await?
            .first()
            .ok_or(KeystoneApiError::NotFound {
                resource: "mapping".into(),
                identifier: mapping_name.clone(),
            })?
            .to_owned()
    } else {
        return Err(OidcError::MappingRequired)?;
    };

    // Check for IdP and mapping `enabled` state
    if !idp.enabled {
        return Err(OidcError::IdentityProviderDisabled)?;
    }
    if !mapping.enabled {
        return Err(OidcError::MappingDisabled)?;
    }

    let client = if let Some(discovery_url) = &idp.oidc_discovery_url {
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(OidcError::from)?;

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(discovery_url.to_string()).map_err(OidcError::from)?,
            &http_client,
        )
        .await
        .map_err(|err| OidcError::discovery(&err))?;
        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(idp.oidc_client_id.ok_or(OidcError::ClientIdRequired)?),
            idp.oidc_client_secret.map(ClientSecret::new),
        )
        // Set the URL the user will be redirected to after the authorization process.
        // TODO: Check the redirect uri against mapping.allowed_redirect_uris
        .set_redirect_uri(RedirectUrl::new(req.redirect_uri.clone()).map_err(OidcError::from)?)
    } else {
        return Err(OidcError::ClientWithoutDiscoveryNotSupported)?;
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut oidc_scopes: HashSet<Scope> = if let Some(mapping_scopes) = mapping.oidc_scopes {
        HashSet::from_iter(mapping_scopes.into_iter().map(Scope::new))
    } else {
        HashSet::new()
    };
    oidc_scopes.insert(Scope::new("openid".to_string()));

    // Generate the full authorization URL.
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(oidc_scopes)
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    state
        .provider
        .get_federation_provider()
        .create_auth_state(
            &state,
            AuthState {
                state: csrf_token.secret().clone(),
                nonce: nonce.secret().clone(),
                idp_id: idp.id.clone(),
                mapping_id: mapping.id.clone(),
                redirect_uri: req.redirect_uri.clone(),
                pkce_verifier: pkce_verifier.into_secret(),
                expires_at: (Local::now() + TimeDelta::seconds(180)).into(),
                // TODO: Make this configurable
                scope: req.scope.map(Into::into),
            },
        )
        .await?;

    debug!(
        "url: {:?}, csrf: {:?}, nonce: {:?}",
        auth_url,
        csrf_token.secret(),
        nonce.secret()
    );
    Ok(IdentityProviderAuthResponse {
        auth_url: auth_url.to_string(),
    }
    .into_response())
}
