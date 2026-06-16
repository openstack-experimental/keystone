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
//! # API authentication handling
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use spiffe::SpiffeId;
use tracing::{debug, error};

use openstack_keystone_config::Interface;
use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use crate::api::KeystoneApiError;
use crate::auth::ValidatedSecurityContext;
use crate::keystone::ServiceState;
use crate::mapping::MappingApi;
use crate::token::TokenApi;

#[derive(Debug, Clone)]
pub struct Auth(pub ValidatedSecurityContext);

impl Deref for Auth {
    type Target = ValidatedSecurityContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for Auth
where
    ServiceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = KeystoneApiError;

    #[tracing::instrument(skip(state), err)]
    /// Try to authenticate the request
    ///
    /// Authenticate the request creating the `ValidatedSecurityContext` using
    /// the following information:
    ///
    /// * `mTLS` - SPIFFE issued x509 certificate that is passed as an extension
    ///   by the mtls connection handler. The SVID is flattened into claims and
    ///   routed through the mapping engine for authentication. When matched,
    ///   the `ValidatedSecurityContext` is instantiated as
    ///   `ScopeInfo::Unscoped` scope. System principals (`is_system`) are
    ///   overridden to `ScopeInfo::System`.
    /// * `X-Auth-Token` - HTTP header is used as encoded `FernetToken` which is
    ///   decoded and used
    /// to instantiate the `ValidatedSecurityContext`. The `FernetToken` always
    /// contains the scope information (whether it is scoped or explicitly
    /// Unscoped).
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Only available in tests - get mock ValidatedSecurityContext injected as
        // extension instead of populating mocks for all individual calls.
        #[cfg(any(test, feature = "mock"))]
        {
            if let Some(vsc) = parts.extensions.get::<ValidatedSecurityContext>() {
                vsc.fully_resolved()?;
                return Ok(Auth(vsc.clone()));
            }
        }

        // Extract the interface on which the connection is being served
        // TODO: Insert interface info into the Context
        let interface = parts
            .extensions
            .get::<Interface>()
            .cloned()
            .unwrap_or(Interface::Public);

        let state = Arc::from_ref(state);

        // Check the SPIFFE svid first as the primary identity source
        if let Some(svid) = parts.extensions.get::<SpiffeId>() {
            tracing::debug!("authenticating the spiffe svid {}", svid);

            if let Some(admin_svid) = &state
                .config_manager
                .config
                .read()
                .await
                .interface_admin
                .as_ref()
                .and_then(|admin_if| admin_if.admin_svid.as_ref())
                && interface == Interface::Admin
            {
                // The admin_svid was configured and it is it over the admin interface - short
                // circuit the admin
                let auth_result: AuthenticationResult = AuthenticationResultBuilder::default()
                    .context(AuthenticationContext::Admin)
                    .principal(
                        PrincipalInfoBuilder::default()
                            .identity(IdentityInfo::Principal(
                                PrincipalIdentityInfoBuilder::default()
                                    .id(*admin_svid)
                                    .issuer(svid.trust_domain_name())
                                    .build()?,
                            ))
                            .build()?,
                    )
                    .build()?;

                let mut ctx = SecurityContext::try_from(auth_result)?;
                ctx.set_is_admin();
                let vsc = ValidatedSecurityContext::new_for_scope(
                    ctx,
                    ScopeInfo::System("all".into()),
                    &state,
                )
                .await?;
                return Ok(Auth(vsc));
            }

            // Authenticate via mapping engine (SPIFFE bindings are deprecated — ADR-0020
            // Phase 3)
            let result = state
                .provider
                .get_mapping_provider()
                .authenticate_by_mapping(&state, &flat_spiffe_claims(svid))
                .await?;
            let ctx = SecurityContext::try_from(result)?;
            let vsc =
                ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await?;
            return Ok(Auth(vsc));
        }

        // Now headers can be checked
        if let Some(auth_header) = parts
            .headers
            .get("X-Auth-Token")
            .and_then(|h| h.to_str().ok())
        {
            tracing::debug!("authenticating request with the x-auth-token");
            let vsc = state
                .provider
                .get_token_provider()
                .authorize_by_token(&state, auth_header, Some(false), None)
                .await
                .inspect_err(|e| error!("{:#?}", e))
                .map_err(|_| KeystoneApiError::UnauthorizedNoContext)?;

            vsc.fully_resolved()?;
            return Ok(Auth(vsc));
        }

        debug!("No supported information has been provided.");
        Err(KeystoneApiError::UnauthorizedNoContext)
    }
}

/// Flattens SPIFFE SVID claims into a
/// [`MappingAuthRequest`](crate::mapping::auth::MappingAuthRequest).
///
/// Produces flattened claims with `spiffe.id` and `spiffe.trust_domain` keys.
fn flat_spiffe_claims(svid: &SpiffeId) -> MappingAuthRequest {
    let mut claims = HashMap::new();
    claims.insert("spiffe.id".to_string(), vec![svid.to_string()]);
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec![svid.trust_domain_name().to_string()],
    );

    MappingAuthRequest {
        domain_id: None,
        source: IdentitySource::Spiffe {
            trust_domain: svid.trust_domain_name().to_string(),
        },
        unique_workload_id: svid.to_string(),
        claims,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystone::Service;
    use crate::mapping::MockMappingProvider;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;
    use axum::http::request::Parts;
    use openstack_keystone_config::{AdminInterface, Config, ConfigManager};

    use openstack_keystone_core_types::mapping::MappingProviderError;
    use spiffe::SpiffeId;
    use std::sync::Arc;

    async fn create_test_state(mapping_provider: MockMappingProvider) -> ServiceState {
        let config = Config::default();
        let config_manager = ConfigManager::not_watched(config);
        let policy_enforcer = Arc::new(MockPolicy::default());
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let provider = Provider::mocked_builder()
            .mock_mapping(mapping_provider)
            .build()
            .unwrap();
        let service = Service {
            config_manager,
            db,
            policy_enforcer,
            provider,
            event_dispatcher: crate::events::EventDispatcher::production(),
            storage: None,
            shutdown: false,
        };
        Arc::new(service)
    }

    fn make_parts() -> Parts {
        let (parts, _) = axum::http::Request::new(()).into_parts();
        parts
    }

    #[tokio::test]
    async fn test_spiffe_auth_success() {
        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_authenticate_by_mapping()
            .once()
            .returning(|_, _| {
                Ok(AuthenticationResultBuilder::default()
                    .context(AuthenticationContext::Password)
                    .principal(
                        PrincipalInfoBuilder::default()
                            .identity(IdentityInfo::Principal(
                                PrincipalIdentityInfoBuilder::default()
                                    .id("test-user")
                                    .issuer("test.domain")
                                    .build()
                                    .unwrap(),
                            ))
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap())
            });

        let state = create_test_state(mapping_mock).await;
        let mut parts = make_parts();
        parts
            .extensions
            .insert(SpiffeId::new("spiffe://test.domain/test-workload").unwrap());

        let result = Auth::from_request_parts(&mut parts, &state).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_spiffe_auth_failure_no_fallback() {
        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_authenticate_by_mapping()
            .once()
            .returning(|_, _| Err(MappingProviderError::NoMatchingRule));

        let state = create_test_state(mapping_mock).await;
        let mut parts = make_parts();
        parts
            .extensions
            .insert(SpiffeId::new("spiffe://test.domain/test-workload").unwrap());

        let result = Auth::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_spiffe_admin_shortcut() {
        use crate::role::MockRoleProvider;

        let mapping_mock = MockMappingProvider::new();
        let config = Config {
            interface_admin: Some(AdminInterface {
                admin_svid: Some("spiffe://admin".to_string()),
                listener: openstack_keystone_config::UnixSocketListener::default(),
            }),
            ..Default::default()
        };
        let config_manager = ConfigManager::not_watched(config);

        let mut role_mock = MockRoleProvider::new();
        role_mock.expect_list_roles().returning(|_, params| {
            let name = params
                .name
                .clone()
                .unwrap_or_else(|| "unknown-role".to_string());
            Ok(vec![openstack_keystone_core_types::role::Role {
                id: format!("{}-id", name),
                name,
                description: None,
                domain_id: None,
                extra: Default::default(),
            }])
        });

        let state = Arc::new(Service {
            config_manager,
            db: sea_orm::Database::connect("sqlite::memory:").await.unwrap(),
            policy_enforcer: Arc::new(MockPolicy::default()),
            provider: Provider::mocked_builder()
                .mock_mapping(mapping_mock)
                .mock_role(role_mock)
                .build()
                .unwrap(),
            event_dispatcher: crate::events::EventDispatcher::production(),
            storage: None,
            shutdown: false,
        });

        let mut parts = make_parts();
        parts
            .extensions
            .insert(SpiffeId::new("spiffe://admin").unwrap());
        parts.extensions.insert(Interface::Admin);

        let result = Auth::from_request_parts(&mut parts, &state).await;
        assert!(result.is_ok());
    }
}
