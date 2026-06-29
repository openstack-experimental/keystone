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
//! CADF audit hook and shared initiator-builder helpers (ADR 0023 Phase 3.4).
//!
//! [`CadfAuditHook`] translates `(ValidatedSecurityContext, Event, AuditOutcome)`
//! triples into signed [`CadfEvent`]s and dispatches them via the critical
//! channel of an [`AuditDispatcher`].
//!
//! The initiator-builder helpers are also used by the perimeter audit path in
//! `crates/keystone/src/audit.rs`.

use std::sync::Arc;

use async_trait::async_trait;
use openstack_keystone_audit::sanitize::sanitize_audit_id;
use openstack_keystone_audit::{AuditDispatcher, CadfEventPayload, Initiator, Observer, Target};
use openstack_keystone_core_types::auth::ScopeInfo;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::token::VerifiedFernetToken;
use uuid::Uuid;

use crate::auth::ValidatedSecurityContext;
use crate::events::{AuditDispatchError, AuditHook, AuditOutcome};

/// Map a domain [`Event`] to a CADF action string.
///
/// `Operation::Other` strings are sanitized to `[a-zA-Z0-9/_-]`, capped at
/// 64 characters. An empty result after sanitization maps to `"unknown"`.
pub fn map_event_to_action(event: &Event) -> String {
    match &event.operation {
        Operation::Create => "create".to_string(),
        Operation::Update => "update".to_string(),
        Operation::Delete => "delete".to_string(),
        Operation::Disable => "disable".to_string(),
        Operation::Enable => "enable".to_string(),
        Operation::Authenticate => "authenticate".to_string(),
        Operation::Revoke => "revoke".to_string(),
        Operation::Other(action) => {
            let s: String = action
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/'))
                .take(64)
                .collect();
            if s.is_empty() {
                "unknown".to_string()
            } else {
                s
            }
        }
    }
}

/// Map an [`EventPayload`] to a CADF `(target_id, type_uri)` pair.
///
/// `target_id` is passed through [`sanitize_audit_id`] to enforce UUID format.
fn build_target_from_event(event: &Event) -> Target {
    let (raw_id, type_uri): (&str, &str) = match &event.payload {
        EventPayload::User { id } => (id, "data/security/identity/user"),
        EventPayload::Group { id } => (id, "data/security/identity/group"),
        EventPayload::Project { id } => (id, "data/security/account/project"),
        EventPayload::Domain { id } => (id, "data/security/account/domain"),
        EventPayload::Role { id } => (id, "data/security/authz/role"),
        EventPayload::RoleImply {
            prior_role_id: id, ..
        } => (id, "data/security/authz/role-implication"),
        EventPayload::RoleAssignment { role_id: id, .. } => {
            (id, "data/security/authz/role-assignment")
        }
        EventPayload::ApplicationCredential { id, .. } => {
            (id, "data/security/identity/application-credential")
        }
        EventPayload::AccessRule { id, .. } => (id, "data/security/identity/access-rule"),
        EventPayload::Endpoint { id } => (id, "data/compute/catalog/endpoint"),
        EventPayload::Region { id } => (id, "data/compute/catalog/region"),
        EventPayload::Service { id } => (id, "data/compute/catalog/service"),
        EventPayload::Trust { id } => (id, "data/security/identity/trust"),
    };
    Target {
        id: sanitize_audit_id(raw_id),
        type_uri: type_uri.to_string(),
    }
}

/// Build an [`Initiator`] from a fully resolved [`ValidatedSecurityContext`].
pub fn build_initiator_from_vsc(vsc: &ValidatedSecurityContext) -> Initiator {
    let principal = vsc.inner().principal();
    let user_id = sanitize_audit_id(&principal.get_user_id());
    let project_id = vsc.inner().authorization().and_then(|a| match &a.scope {
        ScopeInfo::Project { project, .. } => Some(sanitize_audit_id(&project.id)),
        ScopeInfo::TrustProject(tpi) => Some(sanitize_audit_id(&tpi.project.id)),
        _ => None,
    });
    let domain_id = principal
        .domain_id()
        .as_deref()
        .map(sanitize_audit_id)
        .or_else(|| {
            vsc.inner().authorization().and_then(|a| match &a.scope {
                ScopeInfo::Domain(d) => Some(sanitize_audit_id(&d.id)),
                _ => None,
            })
        });
    Initiator::new(
        user_id,
        project_id.filter(|id| id != "unknown"),
        domain_id.filter(|id| id != "unknown"),
        None,
    )
}

/// Build an all-`"unknown"` [`Initiator`] for total auth failure.
pub fn build_initiator_unknown() -> Initiator {
    Initiator::new("unknown".to_string(), None, None, None)
}

/// Build an [`Initiator`] from a [`VerifiedFernetToken`].
///
/// Used when a token was crypto-verified but authorization subsequently
/// failed (partial context). The `VerifiedFernetToken` type proves the caller
/// went through the crypto-verification path.
pub fn build_initiator_from_verified_token(token: &VerifiedFernetToken) -> Initiator {
    Initiator::new(
        sanitize_audit_id(token.user_id()),
        token
            .project_id()
            .map(sanitize_audit_id)
            .filter(|id| id != "unknown"),
        token
            .domain_id()
            .map(sanitize_audit_id)
            .filter(|id| id != "unknown"),
        None,
    )
}

fn outcome_str(outcome: &AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Attempt => "attempt",
        AuditOutcome::Success => "success",
        AuditOutcome::Failure { .. } => "failure",
    }
}

fn outcome_reason(outcome: &AuditOutcome) -> Option<String> {
    match outcome {
        AuditOutcome::Failure { reason } => Some(reason.clone()),
        _ => None,
    }
}

/// CADF implementation of [`AuditHook`] (ADR 0023 Phase 3.4).
///
/// Translates `(ValidatedSecurityContext, Event, AuditOutcome)` triples into
/// signed [`CadfEvent`]s and dispatches them via [`AuditDispatcher::dispatch_critical`].
pub struct CadfAuditHook {
    dispatcher: Arc<AuditDispatcher>,
}

impl CadfAuditHook {
    pub fn new(dispatcher: Arc<AuditDispatcher>) -> Self {
        Self { dispatcher }
    }
}

#[async_trait]
impl AuditHook for CadfAuditHook {
    async fn on_auditable_event(
        &self,
        ctx: &ValidatedSecurityContext,
        event: &Event,
        outcome: &AuditOutcome,
    ) -> Result<(), AuditDispatchError> {
        let node_id = self.dispatcher.node_id().to_string();
        let event_id = format!("{}:{}", node_id, Uuid::new_v4());
        let payload = CadfEventPayload::new(
            event_id,
            "1.0".to_string(),
            "default".to_string(),
            ctx.correlation_id().to_string(),
            event.timestamp.to_rfc3339(),
            map_event_to_action(event),
            outcome_str(outcome).to_string(),
            outcome_reason(outcome),
            build_initiator_from_vsc(ctx),
            build_target_from_event(event),
            Observer {
                node_id: node_id.clone(),
                id: format!("service/security/keystone/{node_id}"),
            },
        );
        let signed = payload.sign(&self.dispatcher);
        match self.dispatcher.dispatch_critical(signed).await {
            Ok(()) => Ok(()),
            Err(_) => {
                self.dispatcher.record_postaudit_drop();
                Err(AuditDispatchError::DispatcherDead)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_core_types::events::EventPayload;

    #[test]
    fn map_event_to_action_covers_all_variants() {
        let cases: &[(&Event, &str)] = &[
            (
                &Event::new(Operation::Create, EventPayload::Role { id: "r".into() }),
                "create",
            ),
            (
                &Event::new(Operation::Update, EventPayload::Role { id: "r".into() }),
                "update",
            ),
            (
                &Event::new(Operation::Delete, EventPayload::Role { id: "r".into() }),
                "delete",
            ),
            (
                &Event::new(Operation::Disable, EventPayload::Role { id: "r".into() }),
                "disable",
            ),
            (
                &Event::new(Operation::Enable, EventPayload::Role { id: "r".into() }),
                "enable",
            ),
            (
                &Event::new(
                    Operation::Authenticate,
                    EventPayload::Role { id: "r".into() },
                ),
                "authenticate",
            ),
            (
                &Event::new(Operation::Revoke, EventPayload::Role { id: "r".into() }),
                "revoke",
            ),
            (
                &Event::new(
                    Operation::Other("custom/op".into()),
                    EventPayload::Role { id: "r".into() },
                ),
                "custom/op",
            ),
        ];
        for (event, expected) in cases {
            assert_eq!(map_event_to_action(event), *expected);
        }
    }

    #[test]
    fn map_event_to_action_sanitizes_other() {
        let e = Event::new(
            Operation::Other("<script>alert(1)</script>".into()),
            EventPayload::Role { id: "r".into() },
        );
        let action = map_event_to_action(&e);
        // '<', '>', '(', ')' are stripped; '/' survives as a valid character.
        assert_eq!(action, "scriptalert1/script");
    }

    #[test]
    fn map_event_to_action_other_empty_returns_unknown() {
        let e = Event::new(
            Operation::Other("!!!".into()),
            EventPayload::Role { id: "r".into() },
        );
        assert_eq!(map_event_to_action(&e), "unknown");
    }

    #[test]
    fn build_target_from_event_sanitizes_id() {
        let e = Event::new(
            Operation::Delete,
            EventPayload::User {
                id: "not-a-uuid".into(),
            },
        );
        let target = build_target_from_event(&e);
        assert_eq!(target.id, "unknown");
        assert_eq!(target.type_uri, "data/security/identity/user");
    }

    #[test]
    fn build_initiator_unknown_is_all_unknown() {
        let i = build_initiator_unknown();
        assert_eq!(i.id(), "unknown");
        assert!(i.project_id().is_none());
        assert!(i.domain_id().is_none());
    }
}
