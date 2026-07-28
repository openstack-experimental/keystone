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
//! # Per-request cache scope middleware
//!
//! Establishes the [`openstack_keystone_core::request_cache::RequestCache`]
//! task_local for the duration of each request (see ADR 0030), so provider
//! code anywhere on the request's task can read/write it without a new
//! parameter threaded through every call site. Must be layered onto every
//! independent router entry point (the main router and the SCIM router),
//! since each is its own top-level `Router` and therefore its own set of
//! request tasks.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use openstack_keystone_core::request_cache::RequestCache;

/// Axum middleware that runs the rest of the request inside a fresh,
/// request-scoped [`RequestCache`].
pub async fn with_request_cache(req: Request, next: Next) -> Response {
    RequestCache::scope(next.run(req)).await
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt as _;

    use super::*;
    use openstack_keystone_core::request_cache::{cache_get, cache_set};

    async fn handler() -> String {
        assert_eq!(cache_get::<String>("ns", "k"), None);
        cache_set("ns", "k", "value".to_string());
        cache_get::<String>("ns", "k").unwrap_or_default()
    }

    #[tokio::test]
    async fn test_scope_established_per_request() {
        let app = Router::new()
            .route("/echo", get(handler))
            .layer(axum::middleware::from_fn(with_request_cache));

        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri("/echo").body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"value");
        }
    }
}
