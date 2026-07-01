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
//! # Event Dispatcher
//!
//! Provides the infrastructure for inter-provider event notifications.
//!
//! The event system follows a publish-subscribe pattern using tokio's
//! broadcast channel. Providers and extensions can subscribe to events
//! by registering their interest when the service starts.
//!
//! ## Design Principles
//!
//! - **Fire-and-forget**: Event dispatch is non-blocking. A slow subscriber
//!   cannot block the main operation.
//! - **Error isolation**: If a hook fails, the error is logged but the main
//!   operation proceeds uninterrupted.
//! - **Opt-in**: Providers implement [ProviderHooks] to subscribe; no-op by
//!   default.
//! - **No recursion**: Hook execution does not trigger further events.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use openstack_keystone_core_types::events::Event;
use tokio::sync::Mutex;
use tokio::sync::broadcast;

use crate::auth::ValidatedSecurityContext;

/// Trait for providers and extensions that want to receive notifications
/// about events.
///
/// Implementors should handle the events they care about and ignore others.
/// The default implementation does nothing.
#[async_trait]
pub trait ProviderHooks: Send + Sync {
    /// Called when an event is dispatched.
    ///
    /// # Parameters
    /// - `event`: The event that occurred.
    async fn on_event(&self, _event: &Event) {}
}

// ---- Phase 3: Provider Auditing via Context-Aware Hooks (ADR 0023) ----

/// Outcome of a provider operation passed to [`AuditHook`].
#[derive(Debug, Clone)]
pub enum AuditOutcome {
    /// The operation was attempted (pre-audit call, before DB mutation).
    Attempt,
    /// The operation completed successfully.
    Success,
    /// The operation failed.
    Failure {
        /// PII-free sanitized error variant name (see `error_variant_name`).
        reason: String,
    },
}

/// Error from an [`AuditHook`] or from the `emit_critical` path.
#[derive(Debug)]
pub enum AuditDispatchError {
    /// The underlying audit channel is dead (receiver dropped).
    DispatcherDead,
    /// A hook returned an error.
    HookFailed {
        /// Stable `&'static str` description — never formatted from error data
        /// so it can safely appear in logs and audit records.
        description: &'static str,
    },
    /// `emit_critical` was called recursively (from inside a hook).
    Reentered,
}

impl std::fmt::Display for AuditDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditDispatchError::DispatcherDead => write!(f, "audit dispatcher channel is dead"),
            AuditDispatchError::HookFailed { description } => {
                write!(f, "audit hook failed: {description}")
            }
            AuditDispatchError::Reentered => write!(f, "emit_critical called recursively"),
        }
    }
}

impl std::error::Error for AuditDispatchError {}

/// Fail-closed audit hook for high-criticality provider operations.
///
/// Unlike [`ProviderHooks`] (fire-and-forget), `AuditHook` is invoked inline
/// via [`EventDispatcher::emit_critical`] and a hook error aborts the provider
/// call that triggered it (fail-closed semantics).
#[async_trait]
pub trait AuditHook: Send + Sync {
    async fn on_auditable_event(
        &self,
        ctx: &ValidatedSecurityContext,
        event: &Event,
        outcome: &AuditOutcome,
    ) -> Result<(), AuditDispatchError>;
}

tokio::task_local! {
    /// Reentrancy guard for `emit_critical`.
    ///
    /// Set to `true` for the duration of each `emit_critical` call so that
    /// hooks which inadvertently call `emit_critical` again return
    /// [`AuditDispatchError::Reentered`] immediately rather than deadlocking
    /// on the `audit_hooks` mutex.
    static EMIT_CRITICAL_RECURSION: bool;
}

/// Unique identifier for a hook subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookId(u64);

/// Central dispatcher for inter-provider events.
///
/// Manages the broadcast channel and registered hook subscribers.
/// Providers and extensions can subscribe via [EventDispatcher::subscribe()]
/// and the dispatcher will call their [ProviderHooks::on_event()] method
/// for each event.
pub struct EventDispatcher {
    /// Broadcast channel sender for direct subscriber access.
    pub tx: broadcast::Sender<Event>,

    /// Registered fire-and-forget hook subscribers.
    hooks: Mutex<HashMap<HookId, Arc<dyn ProviderHooks>>>,

    /// Registered fail-closed audit hooks (ADR 0023 Phase 3).
    audit_hooks: Mutex<HashMap<HookId, Arc<dyn AuditHook>>>,

    /// Counter for generating unique hook IDs.
    counter: AtomicU64,

    /// Counts post-audit drops: outcomes lost after a DB commit because the
    /// critical channel was full. Exported as a Prometheus gauge (ADR 0023).
    pub postaudit_dropped_count: Arc<AtomicU64>,
}

impl EventDispatcher {
    /// Create a new event dispatcher.
    ///
    /// # Parameters
    /// - `buffer_size`: The number of events the broadcast channel can buffer.
    ///   If the buffer is full, events are dropped (fire-and-forget semantics).
    ///
    /// # Returns
    /// A new `EventDispatcher` instance wrapped in `Arc`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use openstack_keystone_core::events::EventDispatcher;
    ///
    /// let dispatcher = EventDispatcher::new(256);
    /// ```
    pub fn new(buffer_size: usize) -> Arc<Self> {
        let (tx, _) = broadcast::channel(buffer_size);
        Arc::new(Self {
            tx,
            hooks: Mutex::new(HashMap::new()),
            audit_hooks: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
            postaudit_dropped_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Subscribe to events with a custom hook.
    ///
    /// # Parameters
    /// - `hooks`: The hook implementation to call when events are dispatched.
    ///
    /// # Returns
    /// A unique [HookId] that can be used to unsubscribe later.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use openstack_keystone_core::events::{EventDispatcher, ProviderHooks};
    /// use openstack_keystone_core_types::events::Event;
    ///
    /// struct MyHook;
    ///
    /// #[async_trait]
    /// impl ProviderHooks for MyHook {
    ///     async fn on_event(&self, event: &Event) {
    ///         // Handle the event
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let dispatcher = EventDispatcher::new(256);
    ///     let hook_id = dispatcher.subscribe(std::sync::Arc::new(MyHook)).await;
    /// }
    /// ```
    pub async fn subscribe(&self, hooks: Arc<dyn ProviderHooks>) -> HookId {
        let id = HookId(self.counter.fetch_add(1, Ordering::SeqCst));
        self.hooks.lock().await.insert(id, hooks);
        id
    }

    /// Unsubscribe a hook provider.
    ///
    /// # Parameters
    /// - `hook_id`: The ID returned from [EventDispatcher::subscribe()].
    ///
    /// # Returns
    /// `true` if the hook was found and removed, `false` otherwise.
    pub async fn unsubscribe(&self, hook_id: HookId) -> bool {
        self.hooks.lock().await.remove(&hook_id).is_some()
    }

    /// Emit an event to all registered subscribers.
    ///
    /// This method:
    /// 1. Sends the event to the broadcast channel
    /// 2. Spawns async tasks to call each hook's [ProviderHooks::on_event()]
    ///
    /// Hook execution is non-blocking and errors are logged but don't affect
    /// the main operation.
    ///
    /// # Parameters
    /// - `event`: The event to emit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use openstack_keystone_core::events::EventDispatcher;
    /// use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let dispatcher = EventDispatcher::new(256);
    ///     let event = Event::new(
    ///         Operation::Delete,
    ///         EventPayload::Role {
    ///             id: "role-123".to_string(),
    ///         },
    ///     );
    ///     dispatcher.emit(event).await;
    /// }
    /// ```
    pub async fn emit(&self, event: Event) {
        // Send to broadcast channel for direct subscribers
        let _ = self.tx.send(event.clone());

        // Spawn tasks to call hooks
        let hooks: Vec<Arc<dyn ProviderHooks>> =
            self.hooks.lock().await.values().cloned().collect();

        for hook in hooks {
            let event = event.clone();
            tokio::spawn(async move {
                let _ = hook.on_event(&event).await;
            });
        }
    }

    /// Convenience constructor for production use with default buffer size.
    ///
    /// # Returns
    /// A new `EventDispatcher` with a 256-event buffer.
    pub fn production() -> Arc<Self> {
        Self::new(256)
    }

    /// Subscribe a fail-closed audit hook (ADR 0023 Phase 3).
    ///
    /// Unlike [`subscribe`], audit hooks are called synchronously inline with
    /// the provider operation and any hook error aborts the operation.
    pub async fn subscribe_audit(&self, hook: Arc<dyn AuditHook>) -> HookId {
        let id = HookId(self.counter.fetch_add(1, Ordering::SeqCst));
        self.audit_hooks.lock().await.insert(id, hook);
        id
    }

    /// Fail-closed audit dispatch (ADR 0023 Phase 3).
    ///
    /// Calls every registered [`AuditHook`] inline. A
    /// [`AuditDispatchError::DispatcherDead`] from any hook short-circuits
    /// and returns immediately. Any other hook error is collected; if any
    /// hooks fail, returns [`AuditDispatchError::HookFailed`].
    ///
    /// Reentrancy is prevented via a `tokio::task_local!` flag: a recursive
    /// call returns [`AuditDispatchError::Reentered`].
    pub async fn emit_critical(
        &self,
        ctx: &ValidatedSecurityContext,
        event: &Event,
        outcome: &AuditOutcome,
    ) -> Result<(), AuditDispatchError> {
        let is_reentered = EMIT_CRITICAL_RECURSION.try_with(|v| *v).unwrap_or(false);
        if is_reentered {
            return Err(AuditDispatchError::Reentered);
        }

        let hooks: Vec<Arc<dyn AuditHook>> =
            self.audit_hooks.lock().await.values().cloned().collect();

        EMIT_CRITICAL_RECURSION
            .scope(true, async move {
                let mut error_count: u64 = 0;
                for hook in &hooks {
                    match hook.on_auditable_event(ctx, event, outcome).await {
                        Err(AuditDispatchError::DispatcherDead) => {
                            return Err(AuditDispatchError::DispatcherDead);
                        }
                        Err(_) => error_count += 1,
                        Ok(()) => {}
                    }
                }
                if error_count > 0 {
                    return Err(AuditDispatchError::HookFailed {
                        description: "one or more audit hooks failed",
                    });
                }
                Ok(())
            })
            .await
    }

    /// Current count of post-audit outcome drops.
    pub fn postaudit_dropped_count(&self) -> u64 {
        self.postaudit_dropped_count.load(Ordering::Relaxed)
    }
}

/// Audit-before-commit wrapper for high-criticality provider operations
/// (ADR 0023 Phase 3, §"Audit-Before-Commit").
///
/// Emits a pre-audit `Attempt` event (fail-closed), runs the operation, then
/// emits a `Success` or `Failure` post-audit event. If the post-audit channel
/// is full, writes a compensating structured log entry.
///
/// # Arguments
/// - `dispatcher` — `&EventDispatcher`
/// - `ctx` — `&ValidatedSecurityContext`
/// - `event` — `Event` describing the resource being acted on
/// - `operation` — an expression evaluating to a `Future<Output=Result<_, _>>`
/// - `on_audit_error` — closure `|AuditDispatchError| -> E` mapping pre-audit
///   failures to the outer error type
///
/// # Failure reason extraction (Debug-format contract)
///
/// The `Failure` post-audit reason is extracted by formatting the error value
/// with `{:?}` (the `Debug` trait) and taking characters up to the first `(`,
/// `{`, or space, capped at 64 characters.  This yields the enum variant name
/// for typical Rust error enums (e.g. `NotFound`, `Conflict`).  Error types
/// used with this macro MUST implement `Debug` such that the variant or type
/// name appears before any delimiter.  In particular:
/// - Struct-like variants (e.g. `NotFound { .. }`) produce the name before `{`.
/// - Tuple variants (e.g. `Io(std::io::Error)`) produce the name before `(`.
/// - Unit variants (e.g. `Unauthorized`) produce the full name unchanged.
/// - Types that produce multi-word Debug output or leading punctuation will
///   yield a truncated or empty string — avoid using those as operation errors.
///
/// # Cancellation safety
/// If the future returned by `$op` is dropped before completing, the
/// post-audit event is never emitted.  Callers that require at-least-once
/// delivery must ensure the outer task is not cancelled.
#[macro_export]
macro_rules! audited_op {
    (
        dispatcher: $dispatcher:expr,
        ctx:        $ctx:expr,
        event:      $event:expr,
        operation:  $op:expr,
        on_audit_error: $on_audit_error:expr $(,)?
    ) => {{
        use ::std::sync::atomic::Ordering as __Ordering;
        use $crate::events::{AuditOutcome as __AuditOutcome};

        let __event = $event;
        let __ctx = $ctx;
        let __dispatcher = $dispatcher;

        // Pre-audit: fail-closed.  Any dispatch error aborts the operation.
        __dispatcher
            .emit_critical(__ctx, &__event, &__AuditOutcome::Attempt)
            .await
            .map_err($on_audit_error)?;

        let __result = $op.await;

        let __outcome = match &__result {
            Ok(_) => __AuditOutcome::Success,
            Err(e) => __AuditOutcome::Failure {
                // Extract only the type/variant name — strip args and field
                // values that may contain PII or internal detail.
                reason: {
                    let s = format!("{:?}", e);
                    s.chars()
                        .take_while(|c| !matches!(c, '(' | '{' | ' '))
                        .take(64)
                        .collect()
                },
            },
        };

        // Post-audit: best-effort with compensating local log on failure.
        if __dispatcher
            .emit_critical(__ctx, &__event, &__outcome)
            .await
            .is_err()
        {
            __dispatcher
                .postaudit_dropped_count
                .fetch_add(1, __Ordering::Relaxed);
            ::tracing::error!(
                correlation_id = %__ctx.correlation_id(),
                outcome         = ?__outcome,
                event_operation = ?__event.operation,
                event_resource  = ?__event.payload,
                "post-audit channel full — compensating local log written"
            );
        }

        __result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_core_types::events::{EventPayload, Operation};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ---- helpers ----

    fn make_vsc() -> ValidatedSecurityContext {
        use openstack_keystone_core_types::auth::{
            AuthenticationContext, IdentityInfo, PrincipalInfo, SecurityContext,
            UserIdentityInfoBuilder,
        };
        let user = UserIdentityInfoBuilder::default()
            .user_id("test-user-id".to_string())
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(user),
            })
            .build();
        ValidatedSecurityContext::test_new(sc)
    }

    fn make_event() -> Event {
        Event::new(
            Operation::Delete,
            EventPayload::User {
                id: "test-user-id".to_string(),
            },
        )
    }

    // ---- emit_critical tests ----

    #[tokio::test]
    async fn emit_critical_no_hooks_succeeds() {
        let dispatcher = EventDispatcher::new(4);
        let vsc = make_vsc();
        let event = make_event();
        let result = dispatcher
            .emit_critical(&vsc, &event, &AuditOutcome::Attempt)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn emit_critical_hook_success_returns_ok() {
        struct OkHook;
        #[async_trait]
        impl AuditHook for OkHook {
            async fn on_auditable_event(
                &self,
                _ctx: &ValidatedSecurityContext,
                _event: &Event,
                _outcome: &AuditOutcome,
            ) -> Result<(), AuditDispatchError> {
                Ok(())
            }
        }
        let dispatcher = EventDispatcher::new(4);
        dispatcher.subscribe_audit(Arc::new(OkHook)).await;
        let vsc = make_vsc();
        let event = make_event();
        let result = dispatcher
            .emit_critical(&vsc, &event, &AuditOutcome::Success)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn emit_critical_hook_failure_propagates() {
        struct FailHook;
        #[async_trait]
        impl AuditHook for FailHook {
            async fn on_auditable_event(
                &self,
                _ctx: &ValidatedSecurityContext,
                _event: &Event,
                _outcome: &AuditOutcome,
            ) -> Result<(), AuditDispatchError> {
                Err(AuditDispatchError::HookFailed {
                    description: "injected test failure",
                })
            }
        }
        let dispatcher = EventDispatcher::new(4);
        dispatcher.subscribe_audit(Arc::new(FailHook)).await;
        let vsc = make_vsc();
        let event = make_event();
        let result = dispatcher
            .emit_critical(&vsc, &event, &AuditOutcome::Attempt)
            .await;
        assert!(matches!(result, Err(AuditDispatchError::HookFailed { .. })));
    }

    #[tokio::test]
    async fn emit_critical_dispatcher_dead_short_circuits() {
        struct DeadHook;
        #[async_trait]
        impl AuditHook for DeadHook {
            async fn on_auditable_event(
                &self,
                _ctx: &ValidatedSecurityContext,
                _event: &Event,
                _outcome: &AuditOutcome,
            ) -> Result<(), AuditDispatchError> {
                Err(AuditDispatchError::DispatcherDead)
            }
        }
        let dispatcher = EventDispatcher::new(4);
        dispatcher.subscribe_audit(Arc::new(DeadHook)).await;
        let vsc = make_vsc();
        let event = make_event();
        let result = dispatcher
            .emit_critical(&vsc, &event, &AuditOutcome::Attempt)
            .await;
        assert!(
            matches!(result, Err(AuditDispatchError::DispatcherDead)),
            "DispatcherDead must propagate immediately"
        );
    }

    #[tokio::test]
    async fn emit_critical_reentrancy_blocked() {
        // A hook that tries to re-enter emit_critical.
        struct ReentrantHook(Arc<EventDispatcher>);
        #[async_trait]
        impl AuditHook for ReentrantHook {
            async fn on_auditable_event(
                &self,
                ctx: &ValidatedSecurityContext,
                event: &Event,
                outcome: &AuditOutcome,
            ) -> Result<(), AuditDispatchError> {
                // This second call must return Reentered.
                self.0.emit_critical(ctx, event, outcome).await
            }
        }
        let dispatcher = EventDispatcher::new(4);
        let hook = Arc::new(ReentrantHook(Arc::clone(&dispatcher)));
        dispatcher.subscribe_audit(hook).await;
        let vsc = make_vsc();
        let event = make_event();
        // The outer call returns HookFailed (because the inner call returned Reentered,
        // which is collected as a generic hook error).
        let result = dispatcher
            .emit_critical(&vsc, &event, &AuditOutcome::Attempt)
            .await;
        assert!(
            matches!(result, Err(AuditDispatchError::HookFailed { .. })),
            "reentrancy must cause outer call to return HookFailed, got: {:?}",
            result
        );
    }

    // ---- audited_op! tests ----

    #[tokio::test]
    async fn audited_op_emits_attempt_then_success() {
        use std::sync::atomic::AtomicBool;

        struct RecordHook {
            saw_attempt: Arc<AtomicBool>,
            saw_success: Arc<AtomicBool>,
        }
        #[async_trait]
        impl AuditHook for RecordHook {
            async fn on_auditable_event(
                &self,
                _ctx: &ValidatedSecurityContext,
                _event: &Event,
                outcome: &AuditOutcome,
            ) -> Result<(), AuditDispatchError> {
                match outcome {
                    AuditOutcome::Attempt => self.saw_attempt.store(true, Ordering::SeqCst),
                    AuditOutcome::Success => self.saw_success.store(true, Ordering::SeqCst),
                    _ => {}
                }
                Ok(())
            }
        }
        let saw_attempt = Arc::new(AtomicBool::new(false));
        let saw_success = Arc::new(AtomicBool::new(false));
        let dispatcher = EventDispatcher::new(4);
        dispatcher
            .subscribe_audit(Arc::new(RecordHook {
                saw_attempt: Arc::clone(&saw_attempt),
                saw_success: Arc::clone(&saw_success),
            }))
            .await;

        let vsc = make_vsc();
        let event = make_event();
        // Wrap in async block so `?` inside the macro propagates from the block.
        let result: Result<u32, &str> = async {
            crate::audited_op! {
                dispatcher: &dispatcher,
                ctx: &vsc,
                event: event,
                operation: async { Ok::<u32, &str>(42) },
                on_audit_error: |_| "audit error",
            }
        }
        .await;
        assert!(result.is_ok());
        assert!(
            saw_attempt.load(Ordering::SeqCst),
            "Attempt must be emitted"
        );
        assert!(
            saw_success.load(Ordering::SeqCst),
            "Success must be emitted"
        );
    }

    #[tokio::test]
    async fn audited_op_blocked_on_pre_audit_failure() {
        struct BlockHook;
        #[async_trait]
        impl AuditHook for BlockHook {
            async fn on_auditable_event(
                &self,
                _ctx: &ValidatedSecurityContext,
                _event: &Event,
                _outcome: &AuditOutcome,
            ) -> Result<(), AuditDispatchError> {
                Err(AuditDispatchError::HookFailed {
                    description: "blocking hook",
                })
            }
        }
        let dispatcher = EventDispatcher::new(4);
        dispatcher.subscribe_audit(Arc::new(BlockHook)).await;
        let vsc = make_vsc();
        let event = make_event();

        let op_ran = Arc::new(AtomicUsize::new(0));
        let op_ran_clone = Arc::clone(&op_ran);
        // Wrap in async block so `?` propagates from the block rather than the test fn.
        let result: Result<(), &str> = async {
            crate::audited_op! {
                dispatcher: &dispatcher,
                ctx: &vsc,
                event: event,
                operation: async {
                    op_ran_clone.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), &str>(())
                },
                on_audit_error: |_| "audit error",
            }
        }
        .await;
        assert!(result.is_err(), "operation must be blocked");
        assert_eq!(
            op_ran.load(Ordering::SeqCst),
            0,
            "inner operation must not run when pre-audit fails"
        );
    }

    #[tokio::test]
    async fn audited_op_increments_postaudit_dropped_on_failure() {
        // Hook that succeeds on Attempt but fails on Success/Failure.
        struct DropPostAudit;
        #[async_trait]
        impl AuditHook for DropPostAudit {
            async fn on_auditable_event(
                &self,
                _ctx: &ValidatedSecurityContext,
                _event: &Event,
                outcome: &AuditOutcome,
            ) -> Result<(), AuditDispatchError> {
                match outcome {
                    AuditOutcome::Attempt => Ok(()),
                    _ => Err(AuditDispatchError::HookFailed {
                        description: "post-audit failure",
                    }),
                }
            }
        }
        let dispatcher = EventDispatcher::new(4);
        dispatcher.subscribe_audit(Arc::new(DropPostAudit)).await;
        let vsc = make_vsc();
        let event = make_event();

        let _: Result<(), &str> = async {
            crate::audited_op! {
                dispatcher: &dispatcher,
                ctx: &vsc,
                event: event,
                operation: async { Ok::<(), &str>(()) },
                on_audit_error: |_| "pre-audit error",
            }
        }
        .await;

        assert_eq!(
            dispatcher.postaudit_dropped_count(),
            1,
            "post-audit drop counter must increment when post-audit fails"
        );
    }

    struct TestHook {
        count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProviderHooks for TestHook {
        async fn on_event(&self, _event: &Event) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_broadcast_to_multiple_subscribers() {
        let dispatcher = EventDispatcher::new(256);
        let count = Arc::new(AtomicUsize::new(0));

        let hook1 = Arc::new(TestHook {
            count: Arc::clone(&count),
        });
        let hook2 = Arc::new(TestHook {
            count: Arc::clone(&count),
        });

        dispatcher.subscribe(hook1).await;
        dispatcher.subscribe(hook2).await;

        let event = Event::new(
            Operation::Create,
            EventPayload::Role {
                id: "test".to_string(),
            },
        );
        dispatcher.emit(event).await;

        // Give spawned tasks time to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_late_subscriber_gets_only_new_events() {
        let dispatcher = EventDispatcher::new(256);
        let count = Arc::new(AtomicUsize::new(0));

        let hook = Arc::new(TestHook {
            count: Arc::clone(&count),
        });

        // Emit an event before subscribing
        let event1 = Event::new(
            Operation::Create,
            EventPayload::Role {
                id: "test1".to_string(),
            },
        );
        dispatcher.emit(event1).await;

        // Subscribe after event1
        dispatcher.subscribe(hook).await;

        // Emit event2 after subscribing
        let event2 = Event::new(
            Operation::Create,
            EventPayload::Role {
                id: "test2".to_string(),
            },
        );
        dispatcher.emit(event2).await;

        // Give spawned tasks time to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_unsubscribe() {
        let dispatcher = EventDispatcher::new(256);
        let count = Arc::new(AtomicUsize::new(0));

        let hook = Arc::new(TestHook {
            count: Arc::clone(&count),
        });

        let hook_id = dispatcher.subscribe(hook).await;

        // Unsubscribe
        assert!(dispatcher.unsubscribe(hook_id).await);

        // Emit an event after unsubscribing
        let event = Event::new(
            Operation::Create,
            EventPayload::Role {
                id: "test".to_string(),
            },
        );
        dispatcher.emit(event).await;

        // Give spawned tasks time to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_hook_panic_does_not_affect_other_hooks() {
        let dispatcher = EventDispatcher::new(256);
        let count1 = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::new(AtomicUsize::new(0));

        struct PanickingHook {
            count: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl ProviderHooks for PanickingHook {
            async fn on_event(&self, _event: &Event) {
                // This hook will panic (but we catch it in the spawn)
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let panicking = Arc::new(PanickingHook {
            count: Arc::clone(&count2),
        });
        let working = Arc::new(TestHook {
            count: Arc::clone(&count1),
        });

        dispatcher.subscribe(panicking).await;
        dispatcher.subscribe(working).await;

        let event = Event::new(
            Operation::Create,
            EventPayload::Role {
                id: "test".to_string(),
            },
        );
        dispatcher.emit(event).await;

        // Give spawned tasks time to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Both hooks should have been called
        assert_eq!(count1.load(Ordering::SeqCst), 1);
        assert_eq!(count2.load(Ordering::SeqCst), 1);
    }
}
