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
//! # Federation provider
//!
//! Federation provider implements the functionality necessary for the user
//! federation.
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::federation::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::federation::{FederationApi, FederationProviderError, backend::FederationBackend};
use crate::plugin_manager::PluginManagerApi;

pub struct FederationService {
    backend_driver: Arc<dyn FederationBackend>,
}

impl FederationService {
    /// Create new federation service.
    ///
    /// # Parameters
    /// - `config`: The configuration for the federation service.
    /// - `plugin_manager`: The plugin manager to resolve the federation
    ///   backend.
    ///
    /// # Returns
    /// - `Result<Self, FederationProviderError>` - The newly created
    ///   `FederationService` or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, FederationProviderError> {
        let backend_driver = plugin_manager
            .get_federation_backend(config.federation.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl FederationApi for FederationService {
    /// Cleanup expired resources.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or a
    ///   federation provider error.
    #[tracing::instrument(name = "provider.federation.cleanup", level = "debug", skip_all)]
    async fn cleanup<'a>(&self, ctx: &ExecutionContext<'a>) -> Result<(), FederationProviderError> {
        self.backend_driver.cleanup(ctx.state()).await
    }

    /// Create new auth state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `auth_state`: The authentication state to create.
    ///
    /// # Returns
    /// - `Result<AuthState, FederationProviderError>` - The created `AuthState`
    ///   or an error.
    #[tracing::instrument(
        name = "provider.federation.create_auth_state",
        level = "debug",
        skip_all
    )]
    async fn create_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        auth_state: AuthState,
    ) -> Result<AuthState, FederationProviderError> {
        let auth_state_result = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let auth_state_clone = auth_state.clone();
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::AuthState { id: auth_state.state.clone() },
                ),
                operation: async {
                    backend_driver.create_auth_state(ctx.state(), auth_state_clone).await
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let auth_state_result = self
                .backend_driver
                .create_auth_state(ctx.state(), auth_state)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::AuthState {
                        id: auth_state_result.state.clone(),
                    },
                ))
                .await;
            auth_state_result
        };
        Ok(auth_state_result)
    }

    /// Create Identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `idp`: The identity provider details to create.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, FederationProviderError>` - The created
    ///   `IdentityProvider` or an error.
    #[tracing::instrument(
        name = "provider.federation.create_identity_provider",
        level = "debug",
        skip_all
    )]
    async fn create_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        idp: IdentityProviderCreate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        let mut mod_idp = idp;
        if mod_idp.id.is_none() {
            mod_idp.id = Some(Uuid::new_v4().simple().to_string());
        }
        let provider_id = mod_idp.id.clone().unwrap_or_default();
        let provider = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let mod_idp_clone = mod_idp.clone();
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::IdentityProvider { id: provider_id.clone() },
                ),
                operation: async {
                    backend_driver.create_identity_provider(ctx.state(), mod_idp_clone).await
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let provider = self
                .backend_driver
                .create_identity_provider(ctx.state(), mod_idp)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::IdentityProvider {
                        id: provider.id.clone(),
                    },
                ))
                .await;
            provider
        };
        Ok(provider)
    }

    /// Delete auth state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the auth state to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    #[tracing::instrument(name = "provider.federation.delete_auth_state", level = "debug", skip_all, fields(id = %id))]
    async fn delete_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::AuthState { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_auth_state(ctx.state(), id).await?;
                    Ok::<(), FederationProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_auth_state(ctx.state(), id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::AuthState { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    /// Delete identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    #[tracing::instrument(name = "provider.federation.delete_identity_provider", level = "debug", skip_all, fields(id = %id))]
    async fn delete_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::IdentityProvider { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_identity_provider(ctx.state(), id).await?;
                    Ok::<(), FederationProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_identity_provider(ctx.state(), id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::IdentityProvider { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    /// Get auth state by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the auth state to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<AuthState>, FederationProviderError>` - A `Result`
    ///   containing an `Option` with the auth state if found, or an `Error`.
    #[tracing::instrument(name = "provider.federation.get_auth_state", level = "debug", skip_all, fields(id = %id))]
    async fn get_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        self.backend_driver.get_auth_state(ctx.state(), id).await
    }

    /// Get single IDP by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<IdentityProvider>, FederationProviderError>` - A
    ///   `Result` containing an `Option` with the identity provider if found,
    ///   or an `Error`.
    #[tracing::instrument(name = "provider.federation.get_identity_provider", level = "debug", skip_all, fields(id = %id))]
    async fn get_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        self.backend_driver
            .get_identity_provider(ctx.state(), id)
            .await
    }

    /// Resolve the identity provider trusted for an external token issuer.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `domain_id`: The domain of the request.
    /// - `issuer`: The `iss` value of the external token.
    ///
    /// # Returns
    /// - `Result<Option<IdentityProvider>, FederationProviderError>` - The
    ///   single enabled match in the preferred scope, `None`, or
    ///   `AmbiguousIssuer`.
    #[tracing::instrument(name = "provider.federation.get_identity_provider_by_issuer", level = "debug", skip_all, fields(domain_id = %domain_id, issuer = ?issuer))]
    async fn get_identity_provider_by_issuer<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        issuer: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        let params = IdentityProviderListParameters {
            domain_ids: Some(std::collections::HashSet::from([
                Some(domain_id.to_string()),
                None,
            ])),
            bound_issuer: Some(issuer.to_string()),
            ..Default::default()
        };
        let candidates = self
            .backend_driver
            .list_identity_providers(ctx.state(), &params)
            .await?;
        select_identity_provider_for_issuer(candidates, domain_id, issuer)
    }

    /// List IDP.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters for identity providers.
    ///
    /// # Returns
    /// - `Result<Vec<IdentityProvider>, FederationProviderError>` - A list of
    ///   identity providers or an error.
    #[tracing::instrument(name = "provider.federation.list_identity_providers", level = "debug", skip_all, fields(params = ?params))]
    async fn list_identity_providers<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError> {
        self.backend_driver
            .list_identity_providers(ctx.state(), params)
            .await
    }

    /// Update Identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to update.
    /// - `idp`: The update details for the identity provider.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, FederationProviderError>` - The updated
    ///   `IdentityProvider` or an error.
    #[tracing::instrument(name = "provider.federation.update_identity_provider", level = "debug", skip_all, fields(id = %id))]
    async fn update_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        let provider = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let idp_clone = idp.clone();
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::IdentityProvider { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.update_identity_provider(ctx.state(), id, idp_clone).await
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let provider = self
                .backend_driver
                .update_identity_provider(ctx.state(), id, idp)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::IdentityProvider { id: id.to_string() },
                ))
                .await;
            provider
        };
        Ok(provider)
    }
}

/// Pick the identity provider for `issuer` from the pre-filtered candidates.
///
/// The domain's own identity providers take precedence over global ones
/// (no domain). More than one candidate within the winning scope is
/// ambiguous and fails closed. A disabled winner yields `None` and is not
/// replaced by a lower-precedence identity provider, so disabling a domain's
/// IdP cannot silently fall back to a global one. Candidates of other
/// domains, or without a matching `bound_issuer`, are ignored defensively.
fn select_identity_provider_for_issuer(
    candidates: Vec<IdentityProvider>,
    domain_id: &str,
    issuer: &str,
) -> Result<Option<IdentityProvider>, FederationProviderError> {
    let (mut own, mut global) = (Vec::new(), Vec::new());
    for idp in candidates {
        if idp.bound_issuer.as_deref() != Some(issuer) {
            continue;
        }
        match idp.domain_id.as_deref() {
            Some(d) if d == domain_id => own.push(idp),
            None => global.push(idp),
            Some(_) => {}
        }
    }
    // Scope precedence is decided on existence, not on `enabled`: a disabled
    // IdP of the domain must not let a global one take over.
    let scope = if own.is_empty() { global } else { own };
    if scope.is_empty() {
        tracing::debug!(issuer = ?issuer, domain_id = %domain_id, "no identity provider bound to issuer");
        return Ok(None);
    }
    // Retired (disabled) IdPs bound to the same issuer do not make the
    // lookup ambiguous.
    let mut enabled = scope.into_iter().filter(|idp| idp.enabled);
    match (enabled.next(), enabled.next()) {
        (Some(idp), None) => Ok(Some(idp)),
        (None, _) => {
            tracing::debug!(issuer = ?issuer, domain_id = %domain_id, "identity provider bound to issuer is disabled");
            Ok(None)
        }
        (Some(_), Some(_)) => {
            tracing::warn!(issuer = ?issuer, domain_id = %domain_id, "issuer matches more than one enabled identity provider");
            Err(FederationProviderError::AmbiguousIssuer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://issuer.example";

    fn idp(
        id: &str,
        domain: Option<&str>,
        issuer: Option<&str>,
        enabled: bool,
    ) -> IdentityProvider {
        IdentityProvider {
            id: id.into(),
            name: id.into(),
            domain_id: domain.map(Into::into),
            bound_issuer: issuer.map(Into::into),
            enabled,
            ..Default::default()
        }
    }

    fn pick(
        cands: Vec<IdentityProvider>,
        domain: &str,
    ) -> Result<Option<String>, FederationProviderError> {
        select_identity_provider_for_issuer(cands, domain, ISS).map(|o| o.map(|i| i.id))
    }

    #[test]
    fn no_candidates() {
        assert_eq!(pick(vec![], "d1").unwrap(), None);
    }

    #[test]
    fn same_issuer_in_two_domains_resolves_per_domain() {
        let c = || {
            vec![
                idp("a", Some("d1"), Some(ISS), true),
                idp("b", Some("d2"), Some(ISS), true),
            ]
        };
        assert_eq!(pick(c(), "d1").unwrap(), Some("a".into()));
        assert_eq!(pick(c(), "d2").unwrap(), Some("b".into()));
        assert_eq!(pick(c(), "d3").unwrap(), None);
    }

    #[test]
    fn own_domain_wins_over_global() {
        let c = vec![
            idp("g", None, Some(ISS), true),
            idp("a", Some("d1"), Some(ISS), true),
        ];
        assert_eq!(pick(c, "d1").unwrap(), Some("a".into()));
    }

    #[test]
    fn global_used_when_domain_has_none() {
        let c = vec![
            idp("g", None, Some(ISS), true),
            idp("b", Some("d2"), Some(ISS), true),
        ];
        assert_eq!(pick(c, "d1").unwrap(), Some("g".into()));
    }

    #[test]
    fn duplicate_within_domain_is_ambiguous() {
        let c = vec![
            idp("a", Some("d1"), Some(ISS), true),
            idp("b", Some("d1"), Some(ISS), true),
        ];
        assert!(matches!(
            pick(c, "d1"),
            Err(FederationProviderError::AmbiguousIssuer)
        ));
    }

    #[test]
    fn disabled_duplicate_in_domain_is_not_ambiguous() {
        let c = vec![
            idp("old", Some("d1"), Some(ISS), false),
            idp("new", Some("d1"), Some(ISS), true),
        ];
        assert_eq!(pick(c, "d1").unwrap(), Some("new".into()));
    }

    #[test]
    fn duplicate_global_is_ambiguous() {
        let c = vec![
            idp("g1", None, Some(ISS), true),
            idp("g2", None, Some(ISS), true),
        ];
        assert!(matches!(
            pick(c, "d1"),
            Err(FederationProviderError::AmbiguousIssuer)
        ));
    }

    #[test]
    fn duplicate_global_ignored_when_domain_has_single_match() {
        let c = vec![
            idp("g1", None, Some(ISS), true),
            idp("g2", None, Some(ISS), true),
            idp("a", Some("d1"), Some(ISS), true),
        ];
        assert_eq!(pick(c, "d1").unwrap(), Some("a".into()));
    }

    #[test]
    fn idp_without_bound_issuer_never_matches() {
        let c = vec![idp("a", Some("d1"), None, true), idp("g", None, None, true)];
        assert_eq!(pick(c, "d1").unwrap(), None);
    }

    #[test]
    fn different_issuer_never_matches() {
        let c = vec![idp("a", Some("d1"), Some("https://other.example"), true)];
        assert_eq!(pick(c, "d1").unwrap(), None);
    }

    #[test]
    fn disabled_domain_idp_does_not_fall_back_to_global() {
        let c = vec![
            idp("g", None, Some(ISS), true),
            idp("a", Some("d1"), Some(ISS), false),
        ];
        assert_eq!(pick(c, "d1").unwrap(), None);
    }
}
