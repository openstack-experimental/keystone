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

//! # K8s auth API: authenticate
use axum::{
    Json, debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use openstack_keystone_api_types::error::KeystoneApiError;
use openstack_keystone_api_types::k8s_auth::K8sAuthRequest;
use openstack_keystone_core::api::{
    common::get_authz_info, v4::auth::token::token_impl::build_api_token_v4,
};
use openstack_keystone_core::k8s_auth::{K8sAuthApi, K8sAuthProviderError};
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::token::TokenApi;
use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::scope::{Project, Scope};

use crate::api::types::{Catalog, CatalogService};
use crate::api::v4::auth::token::types::TokenResponse;
use crate::catalog::CatalogApi;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(post))
}

/// Authenticate using the JWT token of the Kubernetes service account.
///
/// This operation takes the JWT token of the Kubernetes service account, K8s
/// auth instance and role name and exchanges them to the Keystone token with
/// the user and scope information from the token restrictions bound with the
/// k8s auth role.
#[utoipa::path(
    post,
    path = "/instances/{instance_id}/auth",
    operation_id = "/k8s_auth/auth:post",
    request_body = K8sAuthRequest,
    responses(
        (
            status = OK,
            description = "Authentication Token object",
            body = TokenResponse,
            headers(
                ("x-subject-token" = String, description = "Keystone token"),
            ),
        ),
    ),
    tag="k8s_auth_instance"
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
    Path(instance_id): Path<String>,
    Json(req): Json<K8sAuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let auth_result = state
        .provider
        .get_k8s_auth_provider()
        .authenticate_by_k8s_sa_token(&state, &req.to_provider_with_instance_id(instance_id))
        .await?;
    let token_restriction = auth_result
        .token_restriction
        .as_ref()
        .ok_or(K8sAuthProviderError::TokenRestrictionMissing)?
        .clone();

    let mut ctx = SecurityContext::try_from(auth_result)?;
    ctx.token_restriction = Some(token_restriction.clone());

    //authn_info.validate()?;
    let authz_info = get_authz_info(
        &state,
        token_restriction
            .project_id
            .as_ref()
            .map(|token_project_id| {
                Scope::Project(Project {
                    id: Some(token_project_id.to_string()),
                    ..Default::default()
                })
            })
            .as_ref(),
    )
    .await?;
    authz_info.validate()?;

    let mut token = state
        .provider
        .get_token_provider()
        .issue_token(&ctx, &authz_info)?;

    token = state
        .provider
        .get_token_provider()
        .expand_token_information(&state, &token)
        .await
        .map_err(KeystoneApiError::forbidden)?;

    let mut api_token = TokenResponse {
        token: build_api_token_v4(&token, &state).await?,
    };
    api_token.validate()?;

    let catalog: Catalog = Catalog(
        state
            .provider
            .get_catalog_provider()
            .get_catalog(&state, true)
            .await?
            .into_iter()
            .map(|(s, es)| CatalogService {
                id: s.id.clone(),
                name: s.name.clone(),
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
            state.provider.get_token_provider().encode_token(&token)?,
        )],
        Json(api_token),
    )
        .into_response())
}
