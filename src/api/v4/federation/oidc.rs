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
//! Finish OIDC login.

use axum::{Json, debug_handler, extract::State, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use eyre::WrapErr;
use std::collections::{HashMap, HashSet};
use tracing::{debug, trace};
use url::Url;
use utoipa_axum::{router::OpenApiRouter, routes};

use openidconnect::core::CoreProviderMetadata;
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl,
    TokenResponse,
};

use crate::api::v4::auth::token::types::{
    Token as ApiResponseToken, TokenResponse as KeystoneTokenResponse,
};
use crate::api::v4::federation::error::OidcError;
use crate::api::v4::federation::types::*;
use crate::api::{Catalog, error::KeystoneApiError};
use crate::auth::{AuthenticatedInfo, AuthenticationError};
use crate::catalog::CatalogApi;
use crate::federation::FederationApi;
use crate::identity::IdentityApi;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::{FederationBuilder, FederationProtocol, UserCreateBuilder};
use crate::identity::types::{Group, GroupCreate, GroupListParameters};
use crate::keystone::ServiceState;
use crate::token::TokenApi;

use super::common::{get_authz_info, map_user_data, validate_bound_claims};

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(callback))
}

/// Authentication callback.
///
/// This operation allows user to exchange the authorization code retrieved from
/// the identity provider after calling the
/// `/v4/federation/identity_providers/{idp_id}/auth` for the Keystone
/// token. When desired scope was passed in that auth initialization call the
/// scoped token is returned (assuming the user is having roles assigned on that
/// scope).
#[utoipa::path(
    post,
    path = "/oidc/callback",
    operation_id = "/federation/oidc:callback",
    responses(
        (status = OK, description = "Authentication Token object", body = KeystoneTokenResponse,
        headers(
            ("x-subject-token" = String, description = "Keystone token"),
        ),
    ),
    ),
    security(("oauth2" = ["openid"])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_auth_callback",
    level = "debug",
    skip(state),
    err(Debug)
)]
#[debug_handler]
pub async fn callback(
    State(state): State<ServiceState>,
    Json(query): Json<AuthCallbackParameters>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let auth_state = state
        .provider
        .get_federation_provider()
        .get_auth_state(&state, &query.state)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "auth state".into(),
            identifier: query.state.clone(),
        })?;

    if auth_state.expires_at < Utc::now() {
        return Err(OidcError::AuthStateExpired)?;
    }

    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state, &auth_state.idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: auth_state.idp_id.clone(),
            })
        })??;

    let mapping = state
        .provider
        .get_federation_provider()
        .get_mapping(&state, &auth_state.mapping_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "mapping".into(),
                identifier: auth_state.mapping_id.clone(),
            })
        })??;

    let token_restrictions = if let Some(tr_id) = &mapping.token_restriction_id {
        state
            .provider
            .get_token_provider()
            .get_token_restriction(&state, tr_id, true)
            .await?
    } else {
        None
    };

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(OidcError::from)?;

    let client = if let Some(discovery_url) = &idp.oidc_discovery_url {
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(discovery_url.to_string()).map_err(OidcError::from)?,
            &http_client,
        )
        .await
        .map_err(|err| OidcError::discovery(&err))?;
        OidcClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(
                idp.oidc_client_id
                    .clone()
                    .ok_or(OidcError::ClientIdRequired)?,
            ),
            idp.oidc_client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(RedirectUrl::new(auth_state.redirect_uri).map_err(OidcError::from)?)
    } else {
        return Err(OidcError::ClientWithoutDiscoveryNotSupported)?;
    };

    // Finish authorization request by exchanging the authorization code for the
    // token.
    let token_response = client
        .exchange_code(AuthorizationCode::new(query.code))
        .map_err(OidcError::from)?
        // Set the PKCE code verifier.
        .set_pkce_verifier(PkceCodeVerifier::new(auth_state.pkce_verifier))
        .request_async(&http_client)
        .await
        .map_err(|err| OidcError::request_token(&err))?;

    //// Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response.id_token().ok_or(OidcError::NoToken)?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(auth_state.nonce))
        .map_err(OidcError::from)?;
    if let Some(bound_issuer) = &idp.bound_issuer
        && Url::parse(bound_issuer)
            .map_err(OidcError::from)
            .wrap_err_with(|| {
                format!("while parsing the mapping bound_issuer url: {bound_issuer}")
            })?
            == *claims.issuer().url()
    {}

    let claims_as_json = serde_json::to_value(claims)?;
    debug!("Claims data {claims_as_json}");

    validate_bound_claims(&mapping, claims, &claims_as_json)?;
    let mapped_user_data = map_user_data(&state, &idp, &mapping, &claims_as_json).await?;
    debug!("Mapped user is {mapped_user_data:?}");

    let user = if let Some(existing_user) = state
        .provider
        .get_identity_provider()
        .find_federated_user(&state, &idp.id, &mapped_user_data.unique_id)
        .await?
    {
        // The user exists already
        existing_user

        // TODO: update user?
    } else {
        // New user
        let mut federated_user: FederationBuilder = FederationBuilder::default();
        federated_user.idp_id(idp.id.clone());
        federated_user.unique_id(mapped_user_data.unique_id.clone());
        federated_user.protocols(vec![FederationProtocol {
            protocol_id: "oidc".into(),
            unique_id: mapped_user_data.unique_id.clone(),
        }]);
        let mut user_builder: UserCreateBuilder = UserCreateBuilder::default();
        user_builder.id(String::new());
        user_builder.domain_id(mapped_user_data.domain_id);
        user_builder.enabled(true);
        user_builder.name(mapped_user_data.user_name);
        user_builder.federated(Vec::from([federated_user
            .build()
            .map_err(IdentityProviderError::from)?]));

        state
            .provider
            .get_identity_provider()
            .create_user(
                &state,
                user_builder.build().map_err(IdentityProviderError::from)?,
            )
            .await?
    };

    if let Some(necessary_group_names) = mapped_user_data.group_names {
        let current_domain_groups: HashMap<String, String> = HashMap::from_iter(
            state
                .provider
                .get_identity_provider()
                .list_groups(
                    &state,
                    &GroupListParameters {
                        domain_id: Some(user.domain_id.clone()),
                        ..Default::default()
                    },
                )
                .await?
                .into_iter()
                .map(|group| (group.name, group.id)),
        );
        let mut group_ids: HashSet<String> = HashSet::new();
        for group_name in necessary_group_names {
            group_ids.insert(
                if let Some(grp_id) = current_domain_groups.get(&group_name) {
                    grp_id.clone()
                } else {
                    state
                        .provider
                        .get_identity_provider()
                        .create_group(
                            &state,
                            GroupCreate {
                                domain_id: user.domain_id.clone(),
                                name: group_name.clone(),
                                ..Default::default()
                            },
                        )
                        .await?
                        .id
                },
            );
        }
        if !group_ids.is_empty() {
            state
                .provider
                .get_identity_provider()
                .set_user_groups(
                    &state,
                    &user.id,
                    HashSet::from_iter(group_ids.iter().map(|i| i.as_str())),
                )
                .await?;
        }
    }
    let user_groups: Vec<Group> = Vec::from_iter(
        state
            .provider
            .get_identity_provider()
            .list_groups_of_user(&state, &user.id)
            .await?,
    );

    let authed_info = AuthenticatedInfo::builder()
        .user_id(user.id.clone())
        .user(user.clone())
        .methods(vec!["openid".into()])
        .idp_id(idp.id.clone())
        .protocol_id("oidc".to_string())
        .user_groups(user_groups)
        .build()
        .map_err(AuthenticationError::from)?;
    authed_info.validate()?;

    let authz_info = get_authz_info(&state, auth_state.scope.as_ref()).await?;
    trace!("Granting the scope: {:?}", authz_info);

    let mut token = state.provider.get_token_provider().issue_token(
        authed_info,
        authz_info,
        token_restrictions.as_ref(),
    )?;

    token = state
        .provider
        .get_token_provider()
        .expand_token_information(&state, &token)
        .await
        .map_err(|_| KeystoneApiError::Forbidden)?;

    let mut api_token = KeystoneTokenResponse {
        token: ApiResponseToken::from_provider_token(&state, &token).await?,
    };
    let catalog: Catalog = state
        .provider
        .get_catalog_provider()
        .get_catalog(&state, true)
        .await?
        .into();
    api_token.token.catalog = Some(catalog);

    trace!("Token response is {:?}", api_token);
    Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state.provider.get_token_provider().encode_token(&token)?,
        )],
        Json(api_token),
    )
        .into_response())
}
