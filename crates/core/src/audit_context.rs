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
//! # Request-scoped audit context
//!
//! The facts every audit record of one request must share: the client
//! address (resolved through the operator's trusted-proxy settings) and the
//! server-generated correlation ID. The HTTP layer establishes the scope once
//! per request, before any handler runs; audit emitters then read it instead
//! of each handler remembering to thread the values through.
//!
//! That is the point of the scope: a perimeter handler that forgets to pass
//! the address still records it, and plugin audit records join the perimeter
//! event of the same login without a new parameter on every layer in between.
//!
//! Like [`crate::request_cache`], outside an established scope (unit tests
//! that call a provider directly, CLI tooling, background jobs) the
//! accessors return `None` and emitters fall back to what they were given.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use cadf::Initiator;

/// The audit facts of one request.
#[derive(Clone, Debug, Default)]
pub struct AuditRequestContext {
    /// Client address after trusted-proxy resolution; `None` for requests
    /// that did not arrive on the public interface.
    pub client_ip: Option<IpAddr>,
    /// The server-generated `x-openstack-request-id`.
    pub correlation_id: Option<String>,
    /// What the request's handlers recorded for the completion record.
    completion: Arc<Mutex<CompletionState>>,
}

/// Facts the authentication layers leave for the completion middleware.
#[derive(Debug, Default)]
struct CompletionState {
    /// Who the request authenticated as, once known.
    initiator: Option<Initiator>,
    /// A handler already emitted its own perimeter record for this request.
    perimeter_emitted: bool,
}

/// What the completion middleware needs to know about a finished request.
#[derive(Debug, Default)]
pub struct RequestCompletion {
    /// The authenticated initiator, if the request got that far.
    pub initiator: Option<Initiator>,
    /// A perimeter record was already emitted by the handler.
    pub perimeter_emitted: bool,
}

tokio::task_local! {
    static AUDIT_REQUEST: AuditRequestContext;
}

impl AuditRequestContext {
    /// A fresh context for one request.
    #[must_use]
    pub fn new(client_ip: Option<IpAddr>, correlation_id: Option<String>) -> Self {
        Self {
            client_ip,
            correlation_id,
            completion: Arc::default(),
        }
    }

    /// Take what the handlers recorded for the completion record.
    #[must_use]
    pub fn completion(&self) -> RequestCompletion {
        let state = self
            .completion
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        RequestCompletion {
            initiator: state.initiator.clone(),
            perimeter_emitted: state.perimeter_emitted,
        }
    }

    /// Run `fut` with `self` established as the current request's audit
    /// context for its duration.
    pub async fn scope<F: Future>(self, fut: F) -> F::Output {
        AUDIT_REQUEST.scope(self, fut).await
    }
}

/// The current request's client address, if a scope is established and the
/// address is known.
#[must_use]
pub fn client_ip() -> Option<IpAddr> {
    AUDIT_REQUEST.try_with(|ctx| ctx.client_ip).ok().flatten()
}

/// Record who the current request authenticated as, for the completion
/// record. A no-op outside an established scope.
pub fn record_initiator(initiator: Initiator) {
    let _ = AUDIT_REQUEST.try_with(|ctx| {
        ctx.completion
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .initiator = Some(initiator);
    });
}

/// Note that a handler emitted its own perimeter record for the current
/// request, so the completion middleware does not emit a second one.
pub fn mark_perimeter_emitted() {
    let _ = AUDIT_REQUEST.try_with(|ctx| {
        ctx.completion
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .perimeter_emitted = true;
    });
}

/// A handle on the current request's audit context, if a scope is
/// established. Needed where work leaves the request's task, such as a
/// synchronous WASM host function that blocks on an async call: task-locals
/// do not follow into the new runtime context, so the caller re-establishes
/// the scope with [`AuditRequestContext::scope`].
#[must_use]
pub fn current() -> Option<AuditRequestContext> {
    AUDIT_REQUEST.try_with(Clone::clone).ok()
}

/// Run `fut` to completion from synchronous code, keeping the calling
/// request's audit context (if any) established inside it.
pub fn block_on_in_scope<F: Future>(fut: F) -> F::Output {
    let ctx = current();
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async move {
            match ctx {
                Some(ctx) => ctx.scope(fut).await,
                None => fut.await,
            }
        })
    })
}

/// The current request's correlation ID, if a scope is established.
#[must_use]
pub fn correlation_id() -> Option<String> {
    AUDIT_REQUEST
        .try_with(|ctx| ctx.correlation_id.clone())
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accessors_are_empty_outside_a_scope() {
        assert_eq!(client_ip(), None);
        assert_eq!(correlation_id(), None);
    }

    #[tokio::test]
    async fn scope_exposes_the_context_to_nested_awaits() {
        let ctx =
            AuditRequestContext::new(Some("203.0.113.7".parse().unwrap()), Some("req-1".into()));
        ctx.scope(async {
            // Visible across an await point on the same task.
            tokio::task::yield_now().await;
            assert_eq!(client_ip(), Some("203.0.113.7".parse().unwrap()));
            assert_eq!(correlation_id().as_deref(), Some("req-1"));
        })
        .await;
        assert_eq!(client_ip(), None);
    }

    #[tokio::test]
    async fn completion_state_is_shared_with_the_scope() {
        let ctx = AuditRequestContext::new(None, None);
        let probe = ctx.clone();
        ctx.scope(async {
            record_initiator(Initiator::new("u".to_string(), None, None, None));
            mark_perimeter_emitted();
        })
        .await;
        let completion = probe.completion();
        assert_eq!(
            completion.initiator.map(|i| i.id().to_string()).as_deref(),
            Some("u")
        );
        assert!(completion.perimeter_emitted);
        // Outside a scope recording is a silent no-op.
        record_initiator(Initiator::new("x".to_string(), None, None, None));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn block_on_in_scope_keeps_the_request_context() {
        let ctx = AuditRequestContext::new(None, Some("req-2".into()));
        ctx.scope(async {
            // A synchronous caller (a WASM host function) blocking on async
            // work must still see the request's correlation ID.
            let seen = block_on_in_scope(async { correlation_id() });
            assert_eq!(seen.as_deref(), Some("req-2"));
        })
        .await;
        // Without a scope it still runs, with no context.
        assert_eq!(block_on_in_scope(async { correlation_id() }), None);
    }
}
