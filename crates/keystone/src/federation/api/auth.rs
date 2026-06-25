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
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{Local, TimeDelta};
use std::collections::HashSet;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::api::error::KeystoneApiError;
use crate::federation::{api::error::OidcError, api::types::*};
use crate::keystone::ServiceState;
use openstack_keystone_core_types::federation::{
    AuthState, MappingListParameters as ProviderMappingListParameters,
};

use super::oidc_utils::{
    build_auth_url, build_http_client, discover, generate_pkce, generate_random_token,
};

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
        .config_manager
        .config
        .read()
        .await
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
        return Err(OidcError::MappingRequired.into());
    };

    // Check for IdP and mapping `enabled` state
    if !idp.enabled {
        return Err(OidcError::IdentityProviderDisabled.into());
    }
    if !mapping.enabled {
        return Err(OidcError::MappingDisabled.into());
    }

    let discovery_url = idp
        .oidc_discovery_url
        .as_deref()
        .ok_or(OidcError::ClientWithoutDiscoveryNotSupported)?;

    let http_client = build_http_client()?;
    let metadata = discover(discovery_url, &http_client)
        .await
        .map_err(|err| OidcError::discovery(discovery_url, &err))?;

    let client_id = idp
        .oidc_client_id
        .as_deref()
        .ok_or(OidcError::ClientIdRequired)?;

    let pkce = generate_pkce();
    let csrf_token = generate_random_token();
    let nonce = generate_random_token();

    let oidc_scopes: Vec<String> = mapping
        .oidc_scopes
        .map(|scopes| {
            // deduplicate against the implicit "openid" scope
            let unique: HashSet<String> = scopes.into_iter().collect();
            unique.into_iter().filter(|s| s != "openid").collect()
        })
        .unwrap_or_default();

    let auth_url = build_auth_url(
        &metadata.authorization_endpoint,
        client_id,
        &req.redirect_uri,
        &oidc_scopes,
        &csrf_token,
        &nonce,
        &pkce.challenge,
    )?;

    state
        .provider
        .get_federation_provider()
        .create_auth_state(
            &state,
            AuthState {
                state: csrf_token.clone(),
                nonce: nonce.clone(),
                idp_id: idp.id.clone(),
                mapping_id: mapping.id.clone(),
                redirect_uri: req.redirect_uri.clone(),
                pkce_verifier: pkce.verifier,
                expires_at: (Local::now() + TimeDelta::seconds(180)).into(),
                // TODO: Make this configurable
                scope: req.scope.map(Into::into),
            },
        )
        .await?;

    debug!(
        "auth_url: {:?}, csrf: {:?}, nonce: {:?}",
        auth_url, csrf_token, nonce,
    );
    Ok((
        StatusCode::OK,
        Json(IdentityProviderAuthResponse {
            auth_url: auth_url.to_string(),
        }),
    )
        .into_response())
}
