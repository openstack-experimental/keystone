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
//! # Wire-level HTTP send boundary for `http_fetch` (ADR 0025 §6.A)
//!
//! `reqwest` is kept out of `core` by the same split already used for
//! `crate::k8s_auth::K8sHttpClient`: a narrow trait here, implemented with
//! `reqwest` in `keystone`. This trait's contract is stricter than
//! `K8sHttpClient`'s in one respect - `K8sHttpClient` talks to an
//! admin-configured, trusted host and may cache/reuse connections freely;
//! `http_fetch` targets a plugin-supplied URL that ADR §6.A treats as
//! adversarial, so every call here carries an already re-resolved,
//! SSRF-validated `SocketAddr` (done in `crate::dynamic_plugin`) that the
//! implementor MUST connect to directly, never re-resolving the host
//! itself - doing so would silently defeat the DNS-rebinding protection
//! this split exists to preserve.
use std::collections::HashMap;
use std::net::SocketAddr;

use async_trait::async_trait;

/// A single HTTP response, as returned by [`DynamicPluginHttpFetcher`].
///
/// Deliberately not `reqwest::Response` - keeps `reqwest` types out of
/// `core`'s public surface. `content_length`, when present, has already been
/// checked by the implementor against `max_body_bytes` (see
/// [`DynamicPluginHttpFetcher::fetch`]) - it is surfaced here only for the
/// caller's own bookkeeping/logging, not as a cap the caller still needs to
/// enforce.
#[derive(Debug)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<u64>,
    pub body: Vec<u8>,
}

/// Executes a single, already-SSRF-validated HTTP call for `http_fetch`.
///
/// Implementations must:
/// - connect to exactly `resolved_addr` - never re-resolve `url`'s host;
/// - never automatically follow redirects (the caller performs bounded, per-hop
///   re-validated manual redirects);
/// - apply `auth_header`, if present, after `headers`, so a guest-supplied
///   header of the same name can never shadow or override it;
/// - enforce `max_body_bytes` while *streaming* the response body, aborting the
///   transfer as soon as the accumulated size crosses the cap, rather than
///   buffering the full body and checking its length afterwards - a compromised
///   or oversized upstream response must not be able to exhaust memory before
///   the cap has a chance to reject it (ADR §6.A).
#[async_trait]
pub trait DynamicPluginHttpFetcher: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn fetch(
        &self,
        method: &str,
        url: &str,
        resolved_addr: SocketAddr,
        headers: &HashMap<String, String>,
        body: Option<&str>,
        timeout_ms: u64,
        auth_header: Option<(&str, &str)>,
        max_body_bytes: usize,
    ) -> Result<FetchResponse, String>;
}
