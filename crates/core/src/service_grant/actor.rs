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
//! Authenticating a delegatable service by its SVID (ADR 0036 §3.1, §4.2).

use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::oauth2_client::{OAuth2ClientResource, spiffe_id_matches_any};

use crate::auth::{ExecutionContext, IntoAuthContext, ValidatedSecurityContext};
use crate::common::SpiffeId;
use crate::keystone::ServiceState;

/// Build the security context of a delegatable service acting as itself
/// (`AuthenticationContext::ServiceClient`), authenticated by an
/// X.509-SVID presented on the internal interface.
///
/// Returns `None` when `client` does not authenticate `svid`: the client is
/// not a live, enabled service grant grantee, none of its `spiffe_ids`
/// matches, or its domain is gone or disabled. The caller must then treat
/// the request as unauthenticated; there is no fallback to the mapping
/// engine (ADR 0036 §4.2).
pub async fn service_client_context(
    state: &ServiceState,
    svid: &SpiffeId,
    client: &OAuth2ClientResource,
) -> Result<Option<ValidatedSecurityContext>, AuthenticationError> {
    if client.service_grant_policy().is_none()
        || !spiffe_id_matches_any(&client.spiffe_ids, svid.as_str())
    {
        return Ok(None);
    }
    let Some(domain) = state
        .provider
        .get_resource_provider()
        .get_domain(&ExecutionContext::internal(state), &client.domain_id)
        .await
        .auth_context("fetching service client domain")?
        .filter(|d| d.enabled)
    else {
        return Ok(None);
    };

    let auth_result = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::ServiceClient {
            actor: ActorInfo {
                client_id: client.client_id.clone(),
                spiffe_id: svid.to_string(),
            },
        })
        .principal(
            PrincipalInfoBuilder::default()
                .identity(IdentityInfo::Principal(
                    PrincipalIdentityInfoBuilder::default()
                        .id(svid.to_string())
                        .issuer(svid.trust_domain_name())
                        .domain(domain)
                        .build()?,
                ))
                .build()?,
        )
        .build()?;
    let ctx = SecurityContext::try_from(auth_result)?;
    Ok(Some(
        ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, state).await?,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openstack_keystone_core_types::oauth2_client::DelegationPolicy;
    use openstack_keystone_core_types::resource::Domain;

    use super::*;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::tests::get_mocked_state;

    fn client(delegation: Option<DelegationPolicy>) -> OAuth2ClientResource {
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
            delegation,
        }
    }

    fn grants() -> Option<DelegationPolicy> {
        Some(DelegationPolicy {
            service_grants: true,
            ..Default::default()
        })
    }

    async fn state(domain_enabled: bool) -> ServiceState {
        let mut resource = MockResourceProvider::default();
        resource.expect_get_domain().returning(move |_, id| {
            Ok(Some(Domain {
                id: id.to_string(),
                name: "infra".into(),
                enabled: domain_enabled,
                ..Default::default()
            }))
        });
        get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_resource(resource)),
        )
        .await
    }

    #[tokio::test]
    async fn test_matching_svid_builds_service_client() {
        let state = state(true).await;
        let svid = SpiffeId::new("spiffe://td/service/heat-engine/host/h1").unwrap();
        let vsc = service_client_context(&state, &svid, &client(grants()))
            .await
            .unwrap()
            .unwrap();
        match vsc.inner().authentication_context() {
            AuthenticationContext::ServiceClient { actor } => {
                assert_eq!(actor.client_id, "heat-client");
                assert_eq!(actor.spiffe_id, svid.to_string());
            }
            other => panic!("unexpected context {other:?}"),
        }
        assert!(matches!(
            vsc.inner().authorization().map(|a| &a.scope),
            Some(ScopeInfo::Unscoped)
        ));
    }

    #[tokio::test]
    async fn test_non_matching_svid_is_rejected() {
        let state = state(true).await;
        let svid = SpiffeId::new("spiffe://td/service/nova/host/h1").unwrap();
        assert!(
            service_client_context(&state, &svid, &client(grants()))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_non_grantee_client_is_rejected() {
        let state = state(true).await;
        let svid = SpiffeId::new("spiffe://td/service/heat-engine/host/h1").unwrap();
        assert!(
            service_client_context(&state, &svid, &client(None))
                .await
                .unwrap()
                .is_none()
        );
        let mut disabled = client(grants());
        disabled.enabled = false;
        assert!(
            service_client_context(&state, &svid, &disabled)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_disabled_domain_is_rejected() {
        let state = state(false).await;
        let svid = SpiffeId::new("spiffe://td/service/heat-engine/host/h1").unwrap();
        assert!(
            service_client_context(&state, &svid, &client(grants()))
                .await
                .unwrap()
                .is_none()
        );
    }
}
