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
//! Service grant API (ADR 0036 §4.2).
//!
//! OPA input structure for all service_grant operations:
//! ```text
//! {
//!   "credentials": { ... },
//!   "target": { "service_grant": <object-or-null> },
//!   "existing": { "service_grant": <object-or-null> }
//! }
//! ```
//!
//! | Operation | `input.target.service_grant`  | `input.existing.service_grant` |
//! |-----------|-------------------------------|--------------------------------|
//! | Create    | ServiceGrantCreate payload    | null                           |
//! | List      | ServiceGrantListParameters    | null                           |
//! | Show      | null                          | current grant                  |
//! | Delete    | null                          | current grant                  |
//!
//! Show and delete also serve the grantee service on the internal
//! interface, authenticated by its X.509-SVID against the grantee client's
//! `spiffe_ids` ([`Caller`]).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use openstack_keystone_api_types::v4::service_grant::ServiceGrant as ApiServiceGrant;
use openstack_keystone_config::Interface;
use openstack_keystone_core::auth::{ExecutionContext, ValidatedSecurityContext};
use openstack_keystone_core::common::SpiffeId;
use openstack_keystone_core_types::service_grant::ServiceGrant;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::service_grant::service_client_context;

mod create;
mod delete;
mod list;
mod show;

/// OpenApi specification for the service grant API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name="service_grant", description=r#"Service grants (ADR 0036).

A service grant is a user's standing delegation of a subset of their roles on
one project to one registered service client. The service redeems it at the
OAuth2 token endpoint, authenticated by its SPIFFE ID, for a short-lived token
acting for the user.
        "#),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(list::list, create::create))
        .routes(routes!(show::show, delete::remove))
}

/// The caller of show and delete (ADR 0036 §4.2).
pub(super) enum Caller {
    /// A user authenticated the ordinary way.
    User(Box<ValidatedSecurityContext>),
    /// A service presenting an X.509-SVID on the internal interface. It is
    /// authenticated only once the grant names a client whose `spiffe_ids`
    /// match, never through the mapping engine.
    Service(SpiffeId),
}

impl FromRequestParts<ServiceState> for Caller {
    type Rejection = KeystoneApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServiceState,
    ) -> Result<Self, Self::Rejection> {
        if parts.extensions.get::<Interface>() == Some(&Interface::Internal)
            && let Some(svid) = parts.extensions.get::<SpiffeId>()
        {
            return Ok(Self::Service(svid.clone()));
        }
        let Auth(vsc) = Auth::from_request_parts(parts, state).await?;
        Ok(Self::User(Box::new(vsc)))
    }
}

/// Load grant `id` and resolve the security context of `caller` for it.
///
/// A user gets the grant as `None` when it does not exist, so the policy
/// still decides before a 404 tells whether the id exists. A service is
/// authenticated against the grant's grantee client: without the grant
/// there is no client to match, so a missing grant is a 404 directly, and an
/// SVID the grantee client does not accept is a 401.
pub(super) async fn resolve_caller(
    state: &ServiceState,
    caller: Caller,
    id: &str,
) -> Result<(ValidatedSecurityContext, Option<ServiceGrant>), KeystoneApiError> {
    match caller {
        Caller::User(vsc) => {
            let grant = state
                .provider
                .get_service_grant_provider()
                .get_service_grant_by_id(&ExecutionContext::from_auth(state, &vsc), id)
                .await?;
            Ok((*vsc, grant))
        }
        Caller::Service(svid) => {
            let internal = ExecutionContext::internal(state);
            let grant = state
                .provider
                .get_service_grant_provider()
                .get_service_grant_by_id(&internal, id)
                .await?
                .ok_or_else(|| not_found(id))?;
            let client = state
                .provider
                .get_oauth2_client_provider()
                .get_by_client_id(&internal, grant.grantee.client_id())
                .await?
                .ok_or(KeystoneApiError::UnauthorizedNoContext)?;
            let vsc = service_client_context(state, &svid, &client)
                .await?
                .ok_or(KeystoneApiError::UnauthorizedNoContext)?;
            openstack_keystone_core::audit_context::record_initiator(
                openstack_keystone_core::cadf_hook::build_initiator_from_vsc(&vsc),
            );
            Ok((vsc, Some(grant)))
        }
    }
}

/// Policy `existing` input for grant `id`: the grant, or only its id when it
/// does not exist.
pub(super) fn existing_input(id: &str, grant: Option<&ServiceGrant>) -> serde_json::Value {
    match grant {
        Some(grant) => {
            serde_json::json!({"service_grant": ApiServiceGrant::from(grant.clone())})
        }
        None => serde_json::json!({"service_grant": {"id": id}}),
    }
}

pub(super) fn not_found(id: &str) -> KeystoneApiError {
    KeystoneApiError::NotFound {
        resource: "service_grant".into(),
        identifier: id.to_string(),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::HashMap;

    use chrono::Utc;

    use openstack_keystone_core_types::oauth2_client::{DelegationPolicy, OAuth2ClientResource};
    use openstack_keystone_core_types::service_grant::*;

    pub fn grant(id: &str) -> ServiceGrant {
        ServiceGrant {
            id: id.into(),
            version: 1,
            domain_id: "domain_id".into(),
            grantor_user_id: "uid".into(),
            grantee: Grantee::Client {
                client_id: "heat-client".into(),
                client_domain_id: "infra".into(),
            },
            target: GrantTarget::Project {
                project_id: "project_id".into(),
                project_domain_id: "domain_id".into(),
            },
            role_ids: vec!["member".into()],
            expires_at: None,
            description: None,
            enabled: true,
            created_at: Utc::now(),
            last_redeemed_at: None,
            disabled_reason: None,
        }
    }

    pub fn client() -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: "heat-client".into(),
            provider_id: "heat".into(),
            domain_id: "infra".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "tls_client_auth".into(),
            grant_types: vec![],
            require_pkce: false,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: HashMap::new(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: "Heat".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec!["spiffe://td/service/heat-engine/host/*".into()],
            delegation: Some(DelegationPolicy {
                service_grants: true,
                cross_domain: true,
                ..Default::default()
            }),
            dpop_bound_access_tokens: false,
        }
    }
}
