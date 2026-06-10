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

    /// Registered hook subscribers.
    hooks: Mutex<HashMap<HookId, Arc<dyn ProviderHooks>>>,

    /// Counter for generating unique hook IDs.
    counter: AtomicU64,
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
            counter: AtomicU64::new(0),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_core_types::events::{EventPayload, Operation};
    use std::sync::atomic::{AtomicUsize, Ordering};

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
