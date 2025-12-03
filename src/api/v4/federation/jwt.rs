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

//! JWT based authentication API

use axum::{
    Json, debug_handler,
    extract::{Path, State},
    http::HeaderMap,
    http::StatusCode,
    http::header::AUTHORIZATION,
    response::IntoResponse,
};
use std::str::FromStr;
use tracing::warn;
use utoipa_axum::{router::OpenApiRouter, routes};

use openidconnect::core::{
    CoreClient, CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreProviderMetadata,
};
use openidconnect::reqwest;
use openidconnect::{Client, ClientId, IdToken, IssuerUrl, JsonWebKeySet, JsonWebKeySetUrl, Nonce};

use crate::api::v4::auth::token::types::{
    Token as ApiResponseToken, TokenResponse as KeystoneTokenResponse,
};
use crate::api::v4::federation::error::OidcError;
use crate::api::v4::federation::types::*;
use crate::api::{Catalog, error::KeystoneApiError};
use crate::auth::{AuthenticatedInfo, AuthenticationError};
use crate::catalog::CatalogApi;
use crate::federation::FederationApi;
use crate::federation::types::{
    MappingListParameters as ProviderMappingListParameters, MappingType as ProviderMappingType,
    Project as ProviderProject, Scope as ProviderScope,
};
use crate::identity::IdentityApi;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::{FederationBuilder, FederationProtocol, UserCreateBuilder};
use crate::keystone::ServiceState;
use crate::token::TokenApi;

use super::common::{get_authz_info, map_user_data, validate_bound_claims};

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(login))
}

type FullIdToken = IdToken<
    AllOtherClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// Authentication using the JWT.
///
/// This operation allows user to exchange the JWT issued by the trusted
/// identity provider for the regular Keystone session token. Request specifies
/// the necessary authentication mapping, which is also used to validate
/// expected claims.
#[utoipa::path(
    post,
    //path = "/jwt/login",
    path = "/identity_providers/{idp_id}/jwt",
    operation_id = "/federation/identity_provider/jwt:login",
    params(
        ("openstack-mapping" = String, Header, description = "Federated attribute mapping"),

    ),
    responses(
        (status = OK, description = "Authentication Token object", body = KeystoneTokenResponse,
        headers(
            ("x-subject-token" = String, description = "Keystone token"),
        ),
    ),
    ),
    security(("jwt" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_jwt_login",
    level = "debug",
    skip(state),
    err(Debug)
)]
#[debug_handler]
pub async fn login(
    State(state): State<ServiceState>,
    headers: HeaderMap,
    Path(idp_id): Path<String>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .config
        .auth
        .methods
        .iter()
        // TODO: is it how it should be hardcoded?
        // TODO: should be better to use jwt, but it is not available in py-keystone
        .find(|m| *m == "openid")
        .ok_or(KeystoneApiError::AuthMethodNotSupported)?;

    let jwt: String = match headers
        .get(AUTHORIZATION)
        .ok_or(KeystoneApiError::SubjectTokenMissing)?
        .to_str()
        .map_err(|_| KeystoneApiError::InvalidHeader)?
        .split_once(' ')
    {
        Some(("bearer", token)) => token.to_string(),
        _ => return Err(OidcError::BearerJwtTokenMissing.into()),
    };

    let mapping: String = headers
        .get("openstack-mapping")
        .ok_or(OidcError::MappingRequiredJwt)?
        .to_str()
        .map_err(|_| KeystoneApiError::InvalidHeader)?
        .to_string();

    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&state, &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id.clone(),
            })
        })??;

    let mapping = state
        .provider
        .get_federation_provider()
        .list_mappings(
            &state,
            &ProviderMappingListParameters {
                idp_id: Some(idp_id.clone()),
                name: Some(mapping.clone()),
                r#type: Some(ProviderMappingType::Jwt),
                ..Default::default()
            },
        )
        .await?
        .first()
        .ok_or(KeystoneApiError::NotFound {
            resource: "mapping".into(),
            identifier: mapping.clone(),
        })?
        .to_owned();

    // Check for IdP and mapping `enabled` state
    if !idp.enabled {
        return Err(OidcError::IdentityProviderDisabled)?;
    }
    if !mapping.enabled {
        return Err(OidcError::MappingDisabled)?;
    }

    tracing::debug!("Mapping is {:?}", mapping);
    let token_restriction = if let Some(tr_id) = &mapping.token_restriction_id {
        state
            .provider
            .get_token_provider()
            .get_token_restriction(&state, tr_id, true)
            .await?
    } else {
        None
    };

    //if !matches!(mapping.r#type, ProviderMappingType::Jwt) {
    //    // need to log helping message, since the error is wrapped
    //    // to prevent existence exposure.
    //    warn!("Not JWT mapping used for the JWT login");
    //    return Err(OidcError::NonJwtMapping)?;
    //}

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(OidcError::from)?;

    // Discover metadata when issuer or jwks_url is not known
    let provider_metadata: Option<CoreProviderMetadata> = if let Some(discovery_url) =
        &idp.oidc_discovery_url
        && (idp.bound_issuer.is_none() || idp.jwks_url.is_none())
    {
        Some(
            CoreProviderMetadata::discover_async(
                IssuerUrl::new(discovery_url.to_string()).map_err(OidcError::from)?,
                &http_client,
            )
            .await
            .map_err(|err| OidcError::discovery(&err))?,
        )
    } else {
        None
    };

    let issuer_url = if let Some(bound_issuer) = &idp.bound_issuer {
        IssuerUrl::new(bound_issuer.clone()).map_err(OidcError::from)?
    } else if let Some(metadata) = &provider_metadata {
        metadata.issuer().clone()
    } else {
        warn!("No issuer_url can be determined for {:?}", idp);
        return Err(OidcError::NoJwtIssuer)?;
    };

    let jwks_url = if let Some(jwks_url) = &idp.jwks_url {
        JsonWebKeySetUrl::new(jwks_url.clone()).map_err(OidcError::from)?
    } else if let Some(metadata) = &provider_metadata {
        metadata.jwks_uri().clone()
    } else {
        warn!("No jwks_url can be determined for {:?}", idp);
        return Err(OidcError::NoJwtIssuer)?;
    };

    let jwks: JsonWebKeySet<CoreJsonWebKey> = JsonWebKeySet::fetch_async(&jwks_url, &http_client)
        .await
        .map_err(|err| OidcError::discovery(&err))?;

    // TODO: client_id should match the audience. How to get that?
    let audience = "keystone";
    let client: CoreClient = Client::new(ClientId::new(audience.to_string()), issuer_url, jwks);

    let id_token = FullIdToken::from_str(&jwt)?;

    let id_token_verifier = client.id_token_verifier().require_audience_match(false);
    // The nonce is not used in the JWT flow, so we can ignore it.
    let nonce_verifier = |_nonce: Option<&Nonce>| Ok(());
    let claims = id_token
        .into_claims(&id_token_verifier, &nonce_verifier)
        .map_err(OidcError::from)?;

    let claims_as_json = serde_json::to_value(&claims)?;

    validate_bound_claims(&mapping, &claims, &claims_as_json)?;
    let mapped_user_data = map_user_data(&state, &idp, &mapping, &claims_as_json).await?;

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
    let authed_info = AuthenticatedInfo::builder()
        .user_id(user.id.clone())
        .user(user.clone())
        .methods(vec!["openid".into()])
        .idp_id(idp.id.clone())
        .protocol_id("jwt".to_string())
        .build()
        .map_err(AuthenticationError::from)?;
    authed_info.validate()?;

    // TODO: detect scope from the mapping or claims
    let authz_info = get_authz_info(
        &state,
        mapping
            .token_project_id
            .as_ref()
            .map(|token_project_id| {
                ProviderScope::Project(ProviderProject {
                    id: Some(token_project_id.to_string()),
                    ..Default::default()
                })
            })
            .as_ref(),
    )
    .await?;

    let mut token = state.provider.get_token_provider().issue_token(
        authed_info,
        authz_info,
        token_restriction.as_ref(),
    )?;

    // TODO: roles should be granted for the jwt login already

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
