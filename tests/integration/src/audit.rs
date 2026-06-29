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
//! Integration tests for ADR 0023 audit infrastructure (Phase 5.2).
//!
//! These tests verify end-to-end behavior of the audit pipeline as seen from
//! the integration-test harness:
//!
//! 1. A registered `CadfAuditHook` receives events dispatched via
//!    `emit_critical` and forwards signed `CadfEvent`s to the audit channel.
//! 2. A failing `AuditHook` blocks the operation (fail-closed semantics).
//! 3. The `postaudit_dropped_count` on `EventDispatcher` increments when the
//!    post-audit call fails.

use std::sync::Arc;

use async_trait::async_trait;
use eyre::Result;
use openstack_keystone_audit::AuditDispatcher;
use openstack_keystone_core::auth::ValidatedSecurityContext;
use openstack_keystone_core::cadf_hook::CadfAuditHook;
use openstack_keystone_core::events::{
    AuditDispatchError, AuditHook, AuditOutcome, EventDispatcher,
};
use openstack_keystone_core_types::auth::{
    AuthenticationContext, IdentityInfo, PrincipalInfo, UserIdentityInfoBuilder,
};
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

fn make_test_vsc() -> ValidatedSecurityContext {
    let user = UserIdentityInfoBuilder::default()
        .user_id("00000000-0000-0000-0000-000000000001".to_string())
        .build()
        .unwrap();
    let sc = openstack_keystone_core_types::auth::SecurityContext::test_build()
        .authentication_context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(user),
        })
        .build();
    ValidatedSecurityContext::test_new(sc)
}

fn make_delete_user_event() -> Event {
    Event::new(
        Operation::Delete,
        EventPayload::User {
            id: "00000000-0000-0000-0000-000000000002".to_string(),
        },
    )
}

/// Verify that a `CadfAuditHook` subscribed on the event dispatcher receives
/// `emit_critical` calls and forwards signed events to the critical channel.
#[tokio::test]
async fn cadf_hook_forwards_events_to_audit_channel() -> Result<()> {
    let key: Arc<[u8]> = Arc::from(b"integration-test-key-0000000000".as_slice());
    let (audit_dispatcher, mut receivers) = AuditDispatcher::new(
        "test-node",
        "00000000-0000-0000-0000-000000000001".to_string(),
        Arc::clone(&key),
        1,
    );
    let event_dispatcher = EventDispatcher::new(4);

    event_dispatcher
        .subscribe_audit(Arc::new(CadfAuditHook::new(Arc::clone(&audit_dispatcher))))
        .await;

    let vsc = make_test_vsc();
    let event = make_delete_user_event();

    event_dispatcher
        .emit_critical(&vsc, &event, &AuditOutcome::Attempt)
        .await
        .expect("emit_critical must succeed");

    // The CadfAuditHook uses the critical channel.
    let received = receivers
        .critical
        .recv()
        .await
        .expect("must receive a CadfEvent on the critical channel");

    assert_eq!(received.payload().action(), "delete");
    assert!(!received.signature().is_empty());

    // Signature must verify against the key.
    assert!(
        audit_dispatcher.verify_hmac(&received, &key),
        "HMAC verification must pass for the forwarded event"
    );

    Ok(())
}

/// Verify that emitting Attempt + Success via `emit_critical` each produce a
/// correctly-labelled event on the critical channel.
#[tokio::test]
async fn cadf_hook_labels_attempt_and_success() -> Result<()> {
    let key: Arc<[u8]> = Arc::from(b"integration-test-key-0000000000".as_slice());
    let (audit_dispatcher, mut receivers) = AuditDispatcher::new(
        "test-node",
        "00000000-0000-0000-0000-000000000001".to_string(),
        Arc::clone(&key),
        1,
    );
    let event_dispatcher = EventDispatcher::new(4);

    event_dispatcher
        .subscribe_audit(Arc::new(CadfAuditHook::new(Arc::clone(&audit_dispatcher))))
        .await;

    let vsc = make_test_vsc();
    let event = make_delete_user_event();

    event_dispatcher
        .emit_critical(&vsc, &event, &AuditOutcome::Attempt)
        .await
        .expect("Attempt emit must succeed");

    event_dispatcher
        .emit_critical(&vsc, &event, &AuditOutcome::Success)
        .await
        .expect("Success emit must succeed");

    let attempt_ev = receivers.critical.recv().await.unwrap();
    let success_ev = receivers.critical.recv().await.unwrap();

    assert_eq!(attempt_ev.payload().outcome(), "attempt");
    assert_eq!(success_ev.payload().outcome(), "success");

    Ok(())
}

/// Verify fail-closed semantics: a blocking audit hook must prevent the
/// operation from running when `audited_op!` is used.
#[tokio::test]
async fn fail_closed_hook_blocks_operation() -> Result<()> {
    struct BlockHook;
    #[async_trait]
    impl AuditHook for BlockHook {
        async fn on_auditable_event(
            &self,
            _ctx: &ValidatedSecurityContext,
            _event: &Event,
            _outcome: &AuditOutcome,
        ) -> Result<(), AuditDispatchError> {
            Err(AuditDispatchError::DispatcherDead)
        }
    }

    let event_dispatcher = EventDispatcher::new(4);
    event_dispatcher.subscribe_audit(Arc::new(BlockHook)).await;

    let vsc = make_test_vsc();
    let event = make_delete_user_event();

    let op_ran = std::sync::atomic::AtomicBool::new(false);
    let result: Result<(), &str> = async {
        openstack_keystone_core::audited_op! {
            dispatcher: &event_dispatcher,
            ctx:        &vsc,
            event:      event,
            operation:  async {
                op_ran.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<(), &str>(())
            },
            on_audit_error: |_| "audit dispatch failed",
        }
    }
    .await;

    assert!(result.is_err(), "operation must be blocked when hook fails");
    assert!(
        !op_ran.load(std::sync::atomic::Ordering::SeqCst),
        "inner operation must not run when pre-audit fails"
    );

    Ok(())
}

/// Verify that a post-audit failure increments `postaudit_dropped_count` on
/// the `EventDispatcher` while still returning the operation result.
#[tokio::test]
async fn postaudit_drop_counter_increments_on_failure() -> Result<()> {
    struct AllowAttemptDenyOutcome;
    #[async_trait]
    impl AuditHook for AllowAttemptDenyOutcome {
        async fn on_auditable_event(
            &self,
            _ctx: &ValidatedSecurityContext,
            _event: &Event,
            outcome: &AuditOutcome,
        ) -> Result<(), AuditDispatchError> {
            match outcome {
                AuditOutcome::Attempt => Ok(()),
                _ => Err(AuditDispatchError::HookFailed {
                    description: "post-audit channel full (simulated)",
                }),
            }
        }
    }

    let event_dispatcher = EventDispatcher::new(4);
    event_dispatcher
        .subscribe_audit(Arc::new(AllowAttemptDenyOutcome))
        .await;

    let vsc = make_test_vsc();
    let event = make_delete_user_event();

    let _: Result<(), &str> = async {
        openstack_keystone_core::audited_op! {
            dispatcher: &event_dispatcher,
            ctx:        &vsc,
            event:      event,
            operation:  async { Ok::<(), &str>(()) },
            on_audit_error: |_| "pre-audit error",
        }
    }
    .await;

    assert_eq!(
        event_dispatcher.postaudit_dropped_count(),
        1,
        "post-audit drop counter must be 1 after one lost outcome record"
    );

    Ok(())
}
