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
use tracing::{debug, trace};
use url::Url;
use utoipa_axum::{router::OpenApiRouter, routes};

use openidconnect::core::CoreProviderMetadata;
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl,
    TokenResponse,
};

use crate::api::v4::auth::token::types::TokenResponse as KeystoneTokenResponse;
use crate::api::{
    KeystoneApiError,
    types::{Catalog, CatalogService},
};
use crate::auth::*;
use crate::federation::api::error::OidcError;
use crate::keystone::ServiceState;
use openstack_keystone_api_types::v3::auth::token::TokenBuilder;
use openstack_keystone_core::api::common::get_authz_info;
use openstack_keystone_core_types::auth::AuthenticationResult;
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use super::common;
use super::types::*;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(callback))
}

#[utoipa::path(
    post,
    path = "/oidc/callback",
    operation_id = "/federation/oidc:callback",
    responses(
        (
            status = OK,
            description = "Authentication Token object",
            body = KeystoneTokenResponse,
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
    // Validate auth state
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
        return Err(OidcError::AuthStateExpired.into());
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

    if !idp.enabled {
        return Err(OidcError::IdentityProviderDisabled.into());
    }

    // Build the HTTP client with strict redirect policy.
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
        .map_err(|err| OidcError::discovery(discovery_url, &err))?;
        OidcClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(
                idp.oidc_client_id
                    .clone()
                    .ok_or(OidcError::ClientIdRequired)?,
            ),
            idp.oidc_client_secret.clone().map(ClientSecret::new),
        )
        // Set the redirect_uri to protect the authorization code from being stolen.
        .set_redirect_uri(RedirectUrl::new(auth_state.redirect_uri).map_err(OidcError::from)?)
    } else {
        return Err(OidcError::ClientWithoutDiscoveryNotSupported.into());
    };

    // Exchange the authorization code for the token.
    let token_response = client
        .exchange_code(AuthorizationCode::new(query.code))
        .map_err(OidcError::from)?
        // Set the PKCE code verifier to prevent authorization code injection.
        .set_pkce_verifier(PkceCodeVerifier::new(auth_state.pkce_verifier))
        .request_async(&http_client)
        .await
        .map_err(|err| OidcError::request_token(&err))?;

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response.id_token().ok_or(OidcError::NoToken)?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(auth_state.nonce))
        .map_err(OidcError::from)?;

    // Validate the bound_issuer against the claims issuer URL to prevent token
    // reuse across different IdPs.
    if let Some(bound_issuer) = &idp.bound_issuer
        && Url::parse(bound_issuer)
            .map_err(OidcError::from)
            .wrap_err_with(|| {
                format!("while parsing the mapping bound_issuer url: {bound_issuer}")
            })?
            == *claims.issuer().url()
    {}

    let claims_json = serde_json::to_value(claims)?;
    debug!("Claims data {claims_json}");

    // Delegate to the mapping engine for identity resolution. The
    // `default_mapping_name` from the IdP, when set, is used as a rule name
    // hint for targeted rule matching.
    let flattened = common::flatten_federation_claims(&claims_json).map_err(OidcError::from)?;
    let unique_workload_id = claims.subject().as_str().to_string();

    let domain_id = idp.domain_id.clone().ok_or_else(|| {
        KeystoneApiError::BadRequest("Cannot identify domain_id of the user.".to_string())
    })?;

    let mapping_req = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::Federation {
            idp_id: idp.id.clone(),
        },
        unique_workload_id,
        claims: flattened,
        rule_name: idp.default_mapping_name.clone(),
    };

    let auth_result: AuthenticationResult = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &mapping_req)
        .await?;

    // Resolve scope from the original auth request. The scope may be None
    // (unscoped) or a specific project/domain scope that was requested during
    // OIDC auth init.
    let authz_info = get_authz_info(&state, auth_state.scope.as_ref()).await?;
    trace!("Granting the scope: {:?}", authz_info);

    // Issue token with validated security context.
    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            &state,
            &SecurityContext::try_from(auth_result)?,
            &authz_info,
        )
        .await?;

    let mut api_token = KeystoneTokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };
    let catalog: Catalog = Catalog(
        state
            .provider
            .get_catalog_provider()
            .get_catalog(&state, true)
            .await?
            .into_iter()
            .map(|(s, es)| CatalogService {
                id: s.id.clone(),
                name: s.name(),
                r#type: s.r#type,
                endpoints: es.into_iter().map(Into::into).collect(),
            })
            .collect::<Vec<_>>(),
    );
    api_token.token.catalog = Some(catalog);

    trace!("Token response is {:?}", api_token);
    Ok((
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state
                .provider
                .get_token_provider()
                .encode_token(vsc.token()?)?,
        )],
        Json(api_token),
    )
        .into_response())
}
