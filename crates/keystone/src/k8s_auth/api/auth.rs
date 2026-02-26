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

use crate::api::v4::auth::token::types::TokenResponse;
use crate::api::{
    KeystoneApiError,
    common::get_authz_info,
    types::{Catalog, CatalogService},
};
use crate::catalog::CatalogApi;
use crate::common::types::{Project, Scope};
use crate::k8s_auth::{K8sAuthApi, api::types::K8sAuthRequest};
use crate::keystone::ServiceState;
use crate::token::TokenApi;

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

    let (authn_info, token_restriction) = state
        .provider
        .get_k8s_auth_provider()
        .authenticate_by_k8s_sa_token(&state, &(req, instance_id).into())
        .await?;

    authn_info.validate()?;
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

    let mut token = state.provider.get_token_provider().issue_token(
        authn_info,
        authz_info,
        Some(&token_restriction),
    )?;

    token = state
        .provider
        .get_token_provider()
        .expand_token_information(&state, &token)
        .await
        .map_err(KeystoneApiError::forbidden)?;

    let mut api_token = TokenResponse {
        token: token.build_api_token_v4(&state).await?,
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
