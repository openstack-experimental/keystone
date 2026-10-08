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
//! # OAuth2 session provider hook for inter-provider events.
//!
//! Restores ADR 0026 §13 "Revocation Semantics Parity" with the v3 token
//! path: disabling or deleting a user or a domain, or changing a user's
//! password, tombstones every OP refresh token family it covers and drops
//! the pending pre-auth sessions and device grants that could still mint a
//! new one.

use async_trait::async_trait;
use uuid::Uuid;

use openstack_keystone_core_types::events::{
    Event, EventPayload, Operation, PASSWORD_CHANGE_OPERATION,
};
use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason;

use crate::auth::ExecutionContext;
use crate::cadf_hook::build_initiator_unknown;
use crate::events::ProviderHooks;
use crate::keystone::ServiceState;
use crate::oauth2_session::Oauth2SessionProviderError;
use crate::oauth2_session::audit::emit_oauth2_refresh_family_revoked_event;

/// What a lifecycle event revokes.
#[derive(Debug, PartialEq, Eq)]
enum Revocation<'e> {
    /// Every family of the user, and its authenticated pending grants.
    User {
        user_id: &'e str,
        reason: RefreshTokenRevocationReason,
    },
    /// Every family within the domain, and its pending grants.
    Domain {
        domain_id: &'e str,
        reason: RefreshTokenRevocationReason,
    },
}

/// Map an event to the revocation it triggers, if any.
fn revocation_for(event: &Event) -> Option<Revocation<'_>> {
    match (&event.operation, &event.payload) {
        (Operation::Delete, EventPayload::User { id }) => Some(Revocation::User {
            user_id: id,
            reason: RefreshTokenRevocationReason::UserDeleted,
        }),
        (Operation::Disable, EventPayload::User { id }) => Some(Revocation::User {
            user_id: id,
            reason: RefreshTokenRevocationReason::UserDisabled,
        }),
        (Operation::Other(op), EventPayload::User { id }) if op == PASSWORD_CHANGE_OPERATION => {
            Some(Revocation::User {
                user_id: id,
                reason: RefreshTokenRevocationReason::PasswordChanged,
            })
        }
        (Operation::Delete, EventPayload::Domain { id }) => Some(Revocation::Domain {
            domain_id: id,
            reason: RefreshTokenRevocationReason::DomainDeleted,
        }),
        (Operation::Disable, EventPayload::Domain { id }) => Some(Revocation::Domain {
            domain_id: id,
            reason: RefreshTokenRevocationReason::DomainDisabled,
        }),
        _ => None,
    }
}

/// Hook that revokes OAuth2 refresh token families and pending grants when
/// their user or domain is disabled or deleted, or the user's password
/// changes.
pub struct Oauth2SessionHook {
    state: ServiceState,
}

impl Oauth2SessionHook {
    /// Create a new hook bound to the given service state.
    pub fn new(state: ServiceState) -> Self {
        Self { state }
    }

    /// Resolve the domain of a user that still exists, to narrow the family
    /// lookup. `None` (deleted user, failed lookup) searches every domain.
    async fn user_domain(&self, user_id: &str) -> Option<String> {
        match self
            .state
            .provider
            .get_identity_provider()
            .get_user(&ExecutionContext::internal(&self.state), user_id)
            .await
        {
            Ok(user) => user.map(|u| u.domain_id),
            Err(e) => {
                tracing::warn!(
                    user_id,
                    error = %e,
                    "OAuth2 session revocation: user lookup failed, searching every domain",
                );
                None
            }
        }
    }

    async fn revoke(&self, revocation: &Revocation<'_>) -> Result<(), Oauth2SessionProviderError> {
        let provider = self.state.provider.get_oauth2_session_provider();
        let (family_ids, reason) = match *revocation {
            Revocation::User { user_id, reason } => {
                let domain_id = match reason {
                    RefreshTokenRevocationReason::UserDeleted => None,
                    _ => self.user_domain(user_id).await,
                };
                let family_ids = provider
                    .revoke_refresh_token_families_by_user(
                        &self.state,
                        domain_id.as_deref(),
                        user_id,
                        reason,
                    )
                    .await?;
                provider
                    .purge_pending_grants_by_user(&self.state, user_id)
                    .await?;
                provider
                    .delete_sso_sessions_by_user(&self.state, user_id)
                    .await?;
                (family_ids, reason)
            }
            Revocation::Domain { domain_id, reason } => {
                let family_ids = provider
                    .revoke_refresh_token_families_by_domain(&self.state, domain_id, reason)
                    .await?;
                provider
                    .purge_pending_grants_by_domain(&self.state, domain_id)
                    .await?;
                provider
                    .delete_sso_sessions_by_domain(&self.state, domain_id)
                    .await?;
                (family_ids, reason)
            }
        };

        // One correlation id ties together every family revoked by this
        // lifecycle event.
        let correlation_id = format!("req-{}", Uuid::new_v4());
        for family_id in &family_ids {
            emit_oauth2_refresh_family_revoked_event(
                &self.state.audit_dispatcher,
                &correlation_id,
                build_initiator_unknown(),
                family_id,
                reason.as_str(),
            );
        }
        Ok(())
    }
}

#[async_trait]
impl ProviderHooks for Oauth2SessionHook {
    async fn on_event(&self, event: &Event) {
        let Some(revocation) = revocation_for(event) else {
            return;
        };
        // Raft storage is not available in non-raft mode, where there are
        // no OAuth2 sessions to revoke.
        if let Err(e) = self.revoke(&revocation).await
            && !matches!(e, Oauth2SessionProviderError::RaftNotAvailable)
        {
            tracing::error!(
                ?revocation,
                error = %e,
                "Failed to revoke OAuth2 sessions after a lifecycle event",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openstack_keystone_core_types::identity::UserResponseBuilder;

    use crate::identity::MockIdentityProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;
    use crate::tests::get_mocked_state;

    async fn hook_with(
        identity: MockIdentityProvider,
        session: MockOauth2SessionProvider,
    ) -> Oauth2SessionHook {
        Oauth2SessionHook::new(
            get_mocked_state(
                None,
                Some(
                    Provider::mocked_builder()
                        .mock_identity(identity)
                        .mock_oauth2_session(session),
                ),
            )
            .await,
        )
    }

    fn user_in_domain(domain_id: &str) -> MockIdentityProvider {
        let domain_id = domain_id.to_string();
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(move |_, id| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id(id)
                    .domain_id(domain_id.clone())
                    .enabled(false)
                    .name("user")
                    .build()
                    .unwrap(),
            ))
        });
        identity
    }

    fn expect_user_revocation(
        session: &mut MockOauth2SessionProvider,
        domain_id: Option<&'static str>,
        reason: RefreshTokenRevocationReason,
    ) {
        session
            .expect_revoke_refresh_token_families_by_user()
            .withf(move |_, d, u, r| *d == domain_id && u == "user-1" && *r == reason)
            .times(1)
            .returning(|_, _, _, _| Ok(vec!["f1".to_string(), "f2".to_string()]));
        session
            .expect_purge_pending_grants_by_user()
            .withf(|_, u| u == "user-1")
            .times(1)
            .returning(|_, _| Ok(1));
        // The user's browser SSO sessions end with the user.
        session
            .expect_delete_sso_sessions_by_user()
            .withf(|_, u| u == "user-1")
            .times(1)
            .returning(|_, _| Ok(1));
    }

    fn expect_domain_revocation(
        session: &mut MockOauth2SessionProvider,
        reason: RefreshTokenRevocationReason,
    ) {
        session
            .expect_revoke_refresh_token_families_by_domain()
            .withf(move |_, d, r| d == "domain-1" && *r == reason)
            .times(1)
            .returning(|_, _, _| Ok(vec!["f1".to_string()]));
        session
            .expect_purge_pending_grants_by_domain()
            .withf(|_, d| d == "domain-1")
            .times(1)
            .returning(|_, _| Ok(2));
        session
            .expect_delete_sso_sessions_by_domain()
            .withf(|_, d| d == "domain-1")
            .times(1)
            .returning(|_, _| Ok(1));
    }

    fn user_event(operation: Operation) -> Event {
        Event::new(
            operation,
            EventPayload::User {
                id: "user-1".to_string(),
            },
        )
    }

    fn domain_event(operation: Operation) -> Event {
        Event::new(
            operation,
            EventPayload::Domain {
                id: "domain-1".to_string(),
            },
        )
    }

    #[tokio::test]
    async fn test_user_disable_revokes_families_in_user_domain() {
        let mut session = MockOauth2SessionProvider::new();
        expect_user_revocation(
            &mut session,
            Some("domain-1"),
            RefreshTokenRevocationReason::UserDisabled,
        );
        let hook = hook_with(user_in_domain("domain-1"), session).await;
        hook.on_event(&user_event(Operation::Disable)).await;
    }

    #[tokio::test]
    async fn test_user_password_change_revokes_families() {
        let mut session = MockOauth2SessionProvider::new();
        expect_user_revocation(
            &mut session,
            Some("domain-1"),
            RefreshTokenRevocationReason::PasswordChanged,
        );
        let hook = hook_with(user_in_domain("domain-1"), session).await;
        hook.on_event(&user_event(Operation::Other(
            PASSWORD_CHANGE_OPERATION.to_string(),
        )))
        .await;
    }

    #[tokio::test]
    async fn test_user_delete_revokes_families_in_every_domain() {
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().never();
        let mut session = MockOauth2SessionProvider::new();
        expect_user_revocation(
            &mut session,
            None,
            RefreshTokenRevocationReason::UserDeleted,
        );
        let hook = hook_with(identity, session).await;
        hook.on_event(&user_event(Operation::Delete)).await;
    }

    #[tokio::test]
    async fn test_user_disable_for_unknown_user_searches_every_domain() {
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(|_, _| Ok(None));
        let mut session = MockOauth2SessionProvider::new();
        expect_user_revocation(
            &mut session,
            None,
            RefreshTokenRevocationReason::UserDisabled,
        );
        let hook = hook_with(identity, session).await;
        hook.on_event(&user_event(Operation::Disable)).await;
    }

    #[tokio::test]
    async fn test_domain_disable_revokes_families_and_pending_grants() {
        let mut session = MockOauth2SessionProvider::new();
        expect_domain_revocation(&mut session, RefreshTokenRevocationReason::DomainDisabled);
        let hook = hook_with(MockIdentityProvider::default(), session).await;
        hook.on_event(&domain_event(Operation::Disable)).await;
    }

    #[tokio::test]
    async fn test_domain_delete_revokes_families_and_pending_grants() {
        let mut session = MockOauth2SessionProvider::new();
        expect_domain_revocation(&mut session, RefreshTokenRevocationReason::DomainDeleted);
        let hook = hook_with(MockIdentityProvider::default(), session).await;
        hook.on_event(&domain_event(Operation::Delete)).await;
    }

    #[tokio::test]
    async fn test_unrelated_events_revoke_nothing() {
        let mut session = MockOauth2SessionProvider::new();
        session
            .expect_revoke_refresh_token_families_by_user()
            .never();
        session
            .expect_revoke_refresh_token_families_by_domain()
            .never();
        session.expect_purge_pending_grants_by_user().never();
        session.expect_purge_pending_grants_by_domain().never();
        session.expect_delete_sso_sessions_by_user().never();
        session.expect_delete_sso_sessions_by_domain().never();
        let hook = hook_with(MockIdentityProvider::default(), session).await;
        for event in [
            user_event(Operation::Update),
            user_event(Operation::Create),
            user_event(Operation::Enable),
            user_event(Operation::Other("other".to_string())),
            domain_event(Operation::Update),
            domain_event(Operation::Create),
            Event::new(
                Operation::Delete,
                EventPayload::Project {
                    id: "project-1".to_string(),
                },
            ),
        ] {
            hook.on_event(&event).await;
        }
    }

    #[tokio::test]
    async fn test_raft_not_available_is_ignored() {
        let mut session = MockOauth2SessionProvider::new();
        session
            .expect_revoke_refresh_token_families_by_domain()
            .times(1)
            .returning(|_, _, _| Err(Oauth2SessionProviderError::RaftNotAvailable));
        session.expect_purge_pending_grants_by_domain().never();
        session.expect_delete_sso_sessions_by_domain().never();
        let hook = hook_with(MockIdentityProvider::default(), session).await;
        hook.on_event(&domain_event(Operation::Disable)).await;
    }
}
