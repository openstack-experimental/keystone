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
//! # Nova ownership verification (SPIRE integration plan, Phase 2, Fix 1)
//!
//! Before `POST /v4/vendordata` signs an attestation JWT, it must confirm
//! the calling compute host actually owns the instance/project it claims
//! -- otherwise any compute host's shared-per-host SVID could request a
//! signed attestation for an instance it doesn't run. `crates/core` has no
//! `reqwest` dependency (deliberately, so it stays free of any one HTTP
//! client implementation -- see `crates/core/src/auth_plugin_http.rs`),
//! so this module only defines the trait; the `reqwest`-backed
//! implementation lives in `crates/keystone/src/nova_client_impl.rs`,
//! mirroring the existing [`crate::k8s_auth::K8sHttpClient`] /
//! `KeystoneK8sHttpClient` split.
use async_trait::async_trait;
use secrecy::SecretString;

use openstack_keystone_config::NovaAuthScope;
use openstack_keystone_core_types::auth::{
    AuthenticationContext, AuthenticationResultBuilder, AuthzInfoBuilder, IdentityInfo,
    PrincipalIdentityInfoBuilder, PrincipalInfo, ScopeInfo, SecurityContext,
};
use openstack_keystone_core_types::mapping::MappingContext;
use openstack_keystone_core_types::role::{RoleListParametersBuilder, RoleRef};
use openstack_keystone_core_types::vendordata::VendordataProviderError;

use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockNovaClientProvider;

/// The fields of a Nova server record this check needs. Deliberately not
/// the full Nova API response shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NovaServerRecord {
    /// `server.tenant_id`.
    pub tenant_id: String,
    /// `server.OS-EXT-SRV-ATTR:hypervisor_hostname`, gated behind
    /// `os-extended-server-attributes` (admin-only).
    pub hypervisor_hostname: Option<String>,
}

/// Raw HTTP transport to the Nova API. Implemented with `reqwest` in
/// `crates/keystone/src/nova_client_impl.rs`.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait NovaHttpClient: Send + Sync {
    /// Fetch the server record for `instance_id` from Nova, presenting
    /// `admin_token` (a keystone-rs-minted token, see
    /// [`mint_nova_admin_token`]) as `X-Auth-Token`.
    async fn get_server(
        &self,
        instance_id: &str,
        admin_token: &SecretString,
    ) -> Result<NovaServerRecord, VendordataProviderError>;
}

/// Mint a keystone-rs token for calling Nova's admin-gated
/// `os-extended-server-attributes` API (Fix 1, ownership verification).
///
/// keystone-rs has no real user account or role assignment for this
/// identity ("keystone-rs as an OpenStack API caller", ADR 0032 §4): the
/// scope and role names configured under `[vendordata] nova_auth_scope` /
/// `nova_auth_roles` are set directly as the minted token's effective
/// roles, mirroring the same "virtual identity with pre-populated roles"
/// mechanism the SPIFFE/mapping engine (ADR 0020) uses for externally
/// authenticated identities that likewise have no real assignment row.
/// Fails closed (mapped to `503` by the caller) when the scope is
/// unconfigured or a configured role name does not resolve to an existing
/// role.
pub async fn mint_nova_admin_token(
    state: &ServiceState,
) -> Result<SecretString, VendordataProviderError> {
    let vendordata_cfg = state.config_manager.config.read().await.vendordata.clone();
    let auth_scope = vendordata_cfg.nova_auth_scope.ok_or_else(|| {
        VendordataProviderError::NovaUnavailable(
            "[vendordata] nova_auth_scope is not configured".to_string(),
        )
    })?;
    if vendordata_cfg.nova_auth_roles.is_empty() {
        return Err(VendordataProviderError::NovaUnavailable(
            "[vendordata] nova_auth_roles is empty".to_string(),
        ));
    }

    let ctx = ExecutionContext::internal(state);
    let mut roles = Vec::with_capacity(vendordata_cfg.nova_auth_roles.len());
    for role_name in &vendordata_cfg.nova_auth_roles {
        let params = RoleListParametersBuilder::default()
            .name(role_name.clone())
            .build()
            .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;
        let mut found = state
            .provider
            .get_role_provider()
            .list_roles(&ctx, &params)
            .await
            .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;
        let role = found.pop().ok_or_else(|| {
            VendordataProviderError::NovaUnavailable(format!(
                "[vendordata] nova_auth_roles: role {role_name:?} does not exist"
            ))
        })?;
        roles.push(RoleRef::from(role));
    }

    let (scope, is_system) = match auth_scope {
        NovaAuthScope::Project { project_id } => {
            let project = openstack_keystone_core_types::resource::Project {
                id: project_id.clone(),
                name: String::new(),
                description: None,
                enabled: true,
                is_domain: false,
                parent_id: None,
                domain_id: String::new(),
                extra: Default::default(),
                options: Default::default(),
            };
            let project_domain = openstack_keystone_core_types::resource::Domain {
                id: String::new(),
                name: String::new(),
                description: None,
                enabled: true,
                extra: Default::default(),
                options: Default::default(),
            };
            (
                ScopeInfo::Project {
                    project,
                    project_domain,
                },
                false,
            )
        }
        NovaAuthScope::System { system } => (ScopeInfo::System(system), true),
    };

    let principal = PrincipalInfo {
        identity: IdentityInfo::Principal(
            PrincipalIdentityInfoBuilder::default()
                .id("keystone-rs:nova-client")
                .issuer("keystone-rs")
                .build()
                .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?,
        ),
    };
    let auth_context = AuthenticationContext::Mapping(MappingContext {
        mapping_id: "internal:nova-client".to_string(),
        matched_rule_name: "internal:nova-client".to_string(),
        virtual_user_id: "keystone-rs:nova-client".to_string(),
        is_system,
    });
    let mut authz = AuthzInfoBuilder::default()
        .scope(scope.clone())
        .build()
        .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;
    authz.set_roles(roles);

    let auth_result = AuthenticationResultBuilder::default()
        .principal(principal)
        .context(auth_context)
        .authorization(authz)
        .build()
        .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;

    let sc = SecurityContext::try_from(auth_result)
        .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;
    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(state, &sc, &scope)
        .await
        .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;
    let encoded = state
        .provider
        .get_token_provider()
        .encode_token(
            vsc.token()
                .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?,
        )
        .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;

    Ok(SecretString::from(encoded))
}

/// Provider-level API consulted by the `POST /v4/vendordata` handler.
/// Mocked centrally in [`crate::mocks`] as `MockNovaClientProvider`,
/// matching every other top-level provider trait in this crate.
#[async_trait]
pub trait NovaClientApi: Send + Sync {
    /// Returns `Ok(true)` when Nova confirms `instance_id` belongs to
    /// `project_id` and runs on `host`; `Ok(false)` on an explicit
    /// mismatch (handler maps this to `403`); `Err` when the check itself
    /// could not be completed (handler fails closed with `503`).
    async fn verify_ownership(
        &self,
        state: &ServiceState,
        project_id: &str,
        instance_id: &str,
        host: &str,
    ) -> Result<bool, VendordataProviderError>;
}

/// Default [`NovaClientApi`] implementation: delegates the actual HTTP
/// call to an injected [`NovaHttpClient`], then compares the returned
/// record against the caller's claims.
pub struct NovaClientService {
    http_client: std::sync::Arc<dyn NovaHttpClient>,
}

impl NovaClientService {
    /// Create a new `NovaClientService` wrapping `http_client`.
    pub fn new(http_client: std::sync::Arc<dyn NovaHttpClient>) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl NovaClientApi for NovaClientService {
    async fn verify_ownership(
        &self,
        state: &ServiceState,
        project_id: &str,
        instance_id: &str,
        host: &str,
    ) -> Result<bool, VendordataProviderError> {
        let admin_token = mint_nova_admin_token(state).await?;
        let record = self
            .http_client
            .get_server(instance_id, &admin_token)
            .await?;
        Ok(record.tenant_id == project_id && record.hypervisor_hostname.as_deref() == Some(host))
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::role::{Role, RoleBuilder};
    use openstack_keystone_core_types::token::FernetToken;
    use secrecy::ExposeSecret;

    use crate::mocks::{MockRoleProvider, MockTokenProvider};

    use super::*;

    /// Config with `[vendordata] nova_auth_scope`/`nova_auth_roles` set,
    /// mirroring an operator enabling the ownership check.
    fn config_with_nova_scope(scope: NovaAuthScope, roles: Vec<&str>) -> Config {
        let mut config = Config::default();
        config.vendordata.nova_auth_scope = Some(scope);
        config.vendordata.nova_auth_roles = roles.into_iter().map(String::from).collect();
        config
    }

    fn role(id: &str, name: &str) -> Role {
        RoleBuilder::default()
            .id(id)
            .name(name)
            .build()
            .expect("role builds")
    }

    /// `TokenApi` mock that mints a fixed encoded token, mirroring the
    /// pattern in `crates/keystone/src/api/v3/auth/token/create.rs`'s tests:
    /// a canned `ValidatedSecurityContext` carrying a real `FernetToken` (so
    /// `.token()` succeeds) is returned from `issue_token_context`, and
    /// `encode_token` returns the fixed string regardless of its input.
    fn token_mock_minting(encoded: &'static str) -> MockTokenProvider {
        let mut mock = MockTokenProvider::default();
        mock.expect_issue_token_context().returning(|_, _, _| {
            let sc = SecurityContext::test_build()
                .authentication_context(AuthenticationContext::Mapping(MappingContext {
                    mapping_id: "internal:nova-client".into(),
                    matched_rule_name: "internal:nova-client".into(),
                    virtual_user_id: "keystone-rs:nova-client".into(),
                    is_system: false,
                }))
                .principal(PrincipalInfo {
                    identity: IdentityInfo::Principal(
                        PrincipalIdentityInfoBuilder::default()
                            .id("keystone-rs:nova-client")
                            .issuer("keystone-rs")
                            .build()
                            .unwrap(),
                    ),
                })
                .token(FernetToken::Unscoped(Default::default()))
                .build();
            Ok(crate::auth::ValidatedSecurityContext::test_new(sc))
        });
        mock.expect_encode_token()
            .returning(move |_| Ok(encoded.to_string()));
        mock
    }

    #[tokio::test]
    async fn test_mint_nova_admin_token_fails_when_scope_unconfigured() {
        let state = crate::tests::get_mocked_state(None, None).await;
        let result = mint_nova_admin_token(&state).await;
        assert!(matches!(
            result,
            Err(VendordataProviderError::NovaUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn test_mint_nova_admin_token_fails_when_roles_empty() {
        let config = config_with_nova_scope(
            NovaAuthScope::System {
                system: "all".into(),
            },
            vec![],
        );
        let state = crate::tests::get_mocked_state(Some(config), None).await;
        let result = mint_nova_admin_token(&state).await;
        assert!(matches!(
            result,
            Err(VendordataProviderError::NovaUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn test_mint_nova_admin_token_fails_when_role_not_found() {
        let config = config_with_nova_scope(
            NovaAuthScope::System {
                system: "all".into(),
            },
            vec!["admin"],
        );
        let mut role_mock = MockRoleProvider::default();
        role_mock.expect_list_roles().returning(|_, _| Ok(vec![]));
        let provider = crate::provider::Provider::mocked_builder().mock_role(role_mock);
        let state = crate::tests::get_mocked_state(Some(config), Some(provider)).await;

        let result = mint_nova_admin_token(&state).await;
        assert!(matches!(
            result,
            Err(VendordataProviderError::NovaUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn test_mint_nova_admin_token_system_scope_success() {
        let config = config_with_nova_scope(
            NovaAuthScope::System {
                system: "all".into(),
            },
            vec!["admin"],
        );
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .returning(|_, _| Ok(vec![role("rid1", "admin")]));
        let provider = crate::provider::Provider::mocked_builder()
            .mock_role(role_mock)
            .mock_token(token_mock_minting("minted-nova-token"));
        let state = crate::tests::get_mocked_state(Some(config), Some(provider)).await;

        let result = mint_nova_admin_token(&state).await.unwrap();
        assert_eq!(result.expose_secret(), "minted-nova-token");
    }

    #[tokio::test]
    async fn test_mint_nova_admin_token_project_scope_success() {
        let config = config_with_nova_scope(
            NovaAuthScope::Project {
                project_id: "p1".into(),
            },
            vec!["admin"],
        );
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .returning(|_, _| Ok(vec![role("rid1", "admin")]));
        let provider = crate::provider::Provider::mocked_builder()
            .mock_role(role_mock)
            .mock_token(token_mock_minting("minted-nova-token"));
        let state = crate::tests::get_mocked_state(Some(config), Some(provider)).await;

        let result = mint_nova_admin_token(&state).await.unwrap();
        assert_eq!(result.expose_secret(), "minted-nova-token");
    }

    fn mocked_provider_for_verify_ownership() -> crate::provider::ProviderBuilder {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .returning(|_, _| Ok(vec![role("rid1", "admin")]));
        crate::provider::Provider::mocked_builder()
            .mock_role(role_mock)
            .mock_token(token_mock_minting("minted-nova-token"))
    }

    async fn state_for_verify_ownership() -> ServiceState {
        let config = config_with_nova_scope(
            NovaAuthScope::System {
                system: "all".into(),
            },
            vec!["admin"],
        );
        crate::tests::get_mocked_state(Some(config), Some(mocked_provider_for_verify_ownership()))
            .await
    }

    #[tokio::test]
    async fn test_verify_ownership_matches_project_and_host() {
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server().returning(|_, _| {
            Ok(NovaServerRecord {
                tenant_id: "project-1".into(),
                hypervisor_hostname: Some("compute-1".into()),
            })
        });
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = state_for_verify_ownership().await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_verify_ownership_rejects_host_mismatch() {
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server().returning(|_, _| {
            Ok(NovaServerRecord {
                tenant_id: "project-1".into(),
                hypervisor_hostname: Some("compute-2".into()),
            })
        });
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = state_for_verify_ownership().await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_verify_ownership_rejects_project_mismatch() {
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server().returning(|_, _| {
            Ok(NovaServerRecord {
                tenant_id: "other-project".into(),
                hypervisor_hostname: Some("compute-1".into()),
            })
        });
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = state_for_verify_ownership().await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_verify_ownership_propagates_nova_unavailable() {
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server()
            .returning(|_, _| Err(VendordataProviderError::NovaUnavailable("timeout".into())));
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = state_for_verify_ownership().await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await;
        assert!(matches!(
            result,
            Err(VendordataProviderError::NovaUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn test_verify_ownership_fails_closed_when_mint_fails() {
        // No `[vendordata] nova_auth_scope` configured -- minting must fail
        // before the HTTP client is ever invoked.
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server().never();
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = crate::tests::get_mocked_state(None, None).await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await;
        assert!(matches!(
            result,
            Err(VendordataProviderError::NovaUnavailable(_))
        ));
    }
}
