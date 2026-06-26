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
    debug_handler,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use tracing::warn;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::error::KeystoneApiError;
use crate::api::v4::auth::token::types::TokenResponse as KeystoneTokenResponse;
use crate::federation::api::error::OidcError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::AuthenticationResult;
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use super::common;
use super::oidc_utils::{build_http_client, discover, fetch_jwks, verify_jwt};

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(login))
}

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
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.to_string(),
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
        .get_identity_provider(&ExecutionContext::internal(&state), &idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: idp_id,
            })
        })??;

    if !idp.enabled {
        return Err(OidcError::IdentityProviderDisabled.into());
    }

    // Build the HTTP client with strict redirect policy.
    let http_client = build_http_client()?;

    // Discover metadata when issuer or jwks_url is not known.
    let metadata = if let Some(discovery_url) = &idp.oidc_discovery_url
        && (idp.bound_issuer.is_none() || idp.jwks_url.is_none())
    {
        Some(
            discover(discovery_url, &http_client)
                .await
                .map_err(|err| OidcError::discovery(discovery_url, &err))?,
        )
    } else {
        None
    };

    let issuer_url = idp
        .bound_issuer
        .as_deref()
        .map(|s| s.to_string())
        .or_else(|| metadata.as_ref().map(|m| m.issuer.to_string()));

    if issuer_url.is_none() {
        warn!("No issuer_url can be determined for {:?}", idp);
        return Err(OidcError::NoJwtIssuer.into());
    }

    let jwks_url = if let Some(jwks_url) = &idp.jwks_url {
        jwks_url.clone()
    } else if let Some(ref md) = metadata {
        md.jwks_uri.clone()
    } else {
        warn!("No jwks_url can be determined for {:?}", idp);
        return Err(OidcError::NoJwtIssuer.into());
    };

    let jwks = fetch_jwks(&jwks_url, &http_client)
        .await
        .map_err(|err| OidcError::discovery(&jwks_url, &err))?;

    // Verify the JWT and extract claims. In the JWT flow we don't enforce audience
    // matching because the JWT Bearer token is not necessarily issued to the
    // keystone audience. The identity provider handles audience validation through
    // its configured bound_issuer.
    let claims_value: serde_json::Value =
        verify_jwt(&jwt, &jwks, issuer_url.as_deref(), None, &[])?;

    // Flatten claims for the mapping engine. The `sub` claim provides a stable
    // unique identifier for the federated user.
    let flattened = common::flatten_federation_claims(&claims_value)
        .map_err(|_| OidcError::ClaimsMapTooLarge)?;

    // Extract the unique workload identifier from the required `sub` claim.
    // OIDC Core §3.1.2: "REQUIRED subject identifier"
    let unique_workload_id = claims_value["sub"]
        .as_str()
        .ok_or_else(|| {
            KeystoneApiError::BadRequest("`sub` claim is missing from ID token".to_string())
        })?
        .to_string();

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
        .authenticate_by_mapping(&ExecutionContext::internal(&state), &mapping_req)
        .await?;

    // No scope is requested in JWT flow, so we resolve unscoped token.
    let (token_str, api_token) = common::build_token_response(&state, &auth_result, None).await?;

    tracing::trace!("Token response is {:?}", api_token);
    Ok((
        StatusCode::OK,
        [("x-subject-token", token_str)],
        axum::Json(api_token),
    )
        .into_response())
}
