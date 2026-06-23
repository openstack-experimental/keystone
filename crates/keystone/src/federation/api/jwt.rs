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
//! JWT based authentication API.

use axum::{
    Json, debug_handler,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use std::str::FromStr;
use tracing::{trace, warn};
use utoipa_axum::{router::OpenApiRouter, routes};

use openidconnect::core::{
    CoreClient, CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreProviderMetadata,
};
use openidconnect::reqwest;
use openidconnect::{Client, ClientId, IdToken, IssuerUrl, JsonWebKeySet, JsonWebKeySetUrl, Nonce};

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
    OpenApiRouter::new().routes(routes!(login))
}

type FullIdToken = IdToken<
    AllOtherClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

#[utoipa::path(
    post,
    path = "/identity_providers/{idp_id}/jwt",
    operation_id = "/federation/identity_provider/jwt:login",
    params(
        ("openstack-mapping" = String, Header, description = "Rule name hint for targeted rule matching"),
    ),
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
        .config_manager
        .config
        .read()
        .await
        .auth
        .methods
        .iter()
        .find(|m| *m == "openid")
        .ok_or(KeystoneApiError::AuthMethodNotSupported)?;

    // Parse the Bearer token from the Authorization header.
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

    // The `openstack-mapping` header is optional. When present, it specifies a
    // rule name hint that the mapping engine will evaluate first before falling
    // back to the standard first-match-wins iteration.
    let rule_name: Option<String> = if let Some(v) = headers.get("openstack-mapping") {
        Some(
            v.to_str()
                .map_err(|_| KeystoneApiError::InvalidHeader)?
                .to_string(),
        )
    } else {
        None
    };

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

    if !idp.enabled {
        return Err(OidcError::IdentityProviderDisabled.into());
    }

    // Build the HTTP client with strict redirect policy.
    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(OidcError::from)?;

    // Discover metadata when issuer or jwks_url is not known.
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
            .map_err(|err| OidcError::discovery(discovery_url, &err))?,
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
        return Err(OidcError::NoJwtIssuer.into());
    };

    let jwks_url = if let Some(jwks_url) = &idp.jwks_url {
        JsonWebKeySetUrl::new(jwks_url.clone()).map_err(OidcError::from)?
    } else if let Some(metadata) = &provider_metadata {
        metadata.jwks_uri().clone()
    } else {
        warn!("No jwks_url can be determined for {:?}", idp);
        return Err(OidcError::NoJwtIssuer.into());
    };

    let jwks: JsonWebKeySet<CoreJsonWebKey> = JsonWebKeySet::fetch_async(&jwks_url, &http_client)
        .await
        .map_err(|err| OidcError::discovery(jwks_url.as_str(), &err))?;

    let audience = "keystone";
    let client: CoreClient = Client::new(
        ClientId::new(audience.to_string()),
        issuer_url.clone(),
        jwks,
    );

    let id_token = FullIdToken::from_str(&jwt)?;

    // We disable audience matching because the JWT Bearer token is not necessarily
    // issued to the keystone audience. The identity provider handles audience
    // validation through its configured bound_issuer.
    let id_token_verifier = client.id_token_verifier().require_audience_match(false);
    // The nonce is not used in the JWT flow, so we can ignore it.
    let nonce_verifier = |_nonce: Option<&Nonce>| Ok(());
    let claims = id_token
        .into_claims(&id_token_verifier, &nonce_verifier)
        .map_err(OidcError::from)?;

    // Flatten claims for the mapping engine. The `sub` claim provides a stable
    // unique identifier for the federated user.
    let claims_json = serde_json::to_value(&claims)?;
    let flattened = common::flatten_federation_claims(&claims_json).map_err(OidcError::from)?;

    // Extract the unique workload identifier from the `sub` claim.
    let unique_workload_id = claims.subject().as_str().to_string();

    // Delegate to the mapping engine for identity resolution. The rule_name
    // hint from the `openstack-mapping` header allows targeted rule matching.
    let mapping_req = MappingAuthRequest {
        domain_id: idp.domain_id.clone(),
        source: IdentitySource::Federation {
            idp_id: idp.id.clone(),
        },
        unique_workload_id,
        claims: flattened,
        rule_name,
    };

    let auth_result: AuthenticationResult = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&state, &mapping_req)
        .await?;

    // No scope is requested in JWT flow, so we resolve unscoped token.
    let authz_info = get_authz_info(&state, None).await?;
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
