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

/// The audit facts of one request.
#[derive(Clone, Debug, Default)]
pub struct AuditRequestContext {
    /// Client address after trusted-proxy resolution; `None` for requests
    /// that did not arrive on the public interface.
    pub client_ip: Option<IpAddr>,
    /// The server-generated `x-openstack-request-id`.
    pub correlation_id: Option<String>,
}

tokio::task_local! {
    static AUDIT_REQUEST: AuditRequestContext;
}

impl AuditRequestContext {
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
        let ctx = AuditRequestContext {
            client_ip: Some("203.0.113.7".parse().unwrap()),
            correlation_id: Some("req-1".into()),
        };
        ctx.scope(async {
            // Visible across an await point on the same task.
            tokio::task::yield_now().await;
            assert_eq!(client_ip(), Some("203.0.113.7".parse().unwrap()));
            assert_eq!(correlation_id().as_deref(), Some("req-1"));
        })
        .await;
        assert_eq!(client_ip(), None);
    }
}
