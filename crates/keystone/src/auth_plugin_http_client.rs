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
//! # `reqwest`-backed `DynamicPluginHttpFetcher` implementation.
//!
//! Caches a `reqwest::Client` per `(host, port)`, alongside the exact
//! `SocketAddr` and `timeout_ms` it was built with - a plugin's
//! `allowed_hosts` config is static, so it will typically call the same
//! handful of hosts repeatedly, and this lets those calls reuse a warm
//! connection pool instead of paying a fresh TLS handshake every time
//! (mirroring `KeystoneK8sHttpClient`'s per-instance client cache).
//!
//! This does **not** weaken the connect-time SSRF re-validation (ADR 0025
//! §6.A): `resolve_validated_addr` in `openstack_keystone_core::
//! auth_plugin` still re-resolves and re-validates the IP on *every*
//! call, before this cache is even consulted. The cache only decides
//! whether to reuse the already-built client or rebuild it - reuse happens
//! only when the freshly (re-)validated address and timeout are identical
//! to what the cached client was pinned to via `ClientBuilder::resolve`; a
//! changed address (DNS rebinding, failover, config reload) evicts and
//! rebuilds with the new pin, so a stale client can never be used to reach
//! an address that wasn't just re-validated.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use reqwest::{Client, Method};

use openstack_keystone_core::auth_plugin_http::{DynamicPluginHttpFetcher, FetchResponse};

#[derive(Clone)]
struct CachedClient {
    addr: SocketAddr,
    timeout_ms: u64,
    client: Arc<Client>,
}

/// Production `reqwest`-backed [`DynamicPluginHttpFetcher`].
#[derive(Default)]
pub struct KeystoneDynamicPluginHttpFetcher {
    clients: DashMap<(String, u16), CachedClient>,
}

impl KeystoneDynamicPluginHttpFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_or_build_client(
        &self,
        host: &str,
        addr: SocketAddr,
        timeout_ms: u64,
    ) -> Result<Arc<Client>, String> {
        let key = (host.to_string(), addr.port());
        if let Some(cached) = self.clients.get(&key)
            && cached.addr == addr
            && cached.timeout_ms == timeout_ms
        {
            return Ok(Arc::clone(&cached.client));
        }

        let client = Arc::new(
            Client::builder()
                .resolve(host, addr)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_millis(timeout_ms))
                .connect_timeout(Duration::from_millis(timeout_ms))
                .build()
                .map_err(|e| e.to_string())?,
        );
        self.clients.insert(
            key,
            CachedClient {
                addr,
                timeout_ms,
                client: Arc::clone(&client),
            },
        );
        Ok(client)
    }
}

#[async_trait]
impl DynamicPluginHttpFetcher for KeystoneDynamicPluginHttpFetcher {
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
    ) -> Result<FetchResponse, String> {
        let parsed = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "url has no host".to_string())?
            .to_string();
        let method = Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;

        let client = self.get_or_build_client(&host, resolved_addr, timeout_ms)?;

        let mut builder = client.request(method, parsed);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        // Host-injected secret header applied last, after guest headers, so
        // it can never be shadowed or overridden by a guest-supplied header
        // of the same name (ADR §6.A).
        if let Some((name, value)) = auth_header {
            builder = builder.header(name, value);
        }
        if let Some(body) = body {
            builder = builder.body(body.to_string());
        }

        let mut response = builder.send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let content_length = response.content_length();
        let headers_out: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();

        if let Some(len) = content_length
            && len as usize > max_body_bytes
        {
            return Err(format!(
                "response Content-Length {len} exceeds the {max_body_bytes}-byte cap"
            ));
        }

        // Stream and cap incrementally - a response with no (or a lying)
        // Content-Length header must not be able to exhaust memory before
        // the cap is enforced (ADR §6.A).
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            body.extend_from_slice(&chunk);
            if body.len() > max_body_bytes {
                return Err(format!(
                    "response body exceeded the {max_body_bytes}-byte cap"
                ));
            }
        }

        Ok(FetchResponse {
            status,
            headers: headers_out,
            content_length,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method as MockMethod, MockServer};

    use super::*;

    fn host_port(server: &MockServer) -> String {
        format!("{}:{}", server.host(), server.port())
    }

    fn addr_of(server: &MockServer) -> SocketAddr {
        host_port(server).parse().unwrap()
    }

    #[tokio::test]
    async fn test_fetch_round_trips_status_headers_and_body() {
        let server = MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(MockMethod::GET).path("/data");
            then.status(200)
                .header("content-type", "text/plain")
                .body("hello");
        });

        let fetcher = KeystoneDynamicPluginHttpFetcher::new();
        let response = fetcher
            .fetch(
                "GET",
                &format!("http://{}/data", host_port(&server)),
                addr_of(&server),
                &HashMap::new(),
                None,
                5_000,
                None,
                1_000_000,
            )
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert!(
            response
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "text/plain")
        );
    }

    #[tokio::test]
    async fn test_fetch_never_follows_redirects_automatically() {
        let server = MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(MockMethod::GET).path("/old");
            then.status(302).header("location", "/new");
        });

        let fetcher = KeystoneDynamicPluginHttpFetcher::new();
        let response = fetcher
            .fetch(
                "GET",
                &format!("http://{}/old", host_port(&server)),
                addr_of(&server),
                &HashMap::new(),
                None,
                5_000,
                None,
                1_000_000,
            )
            .await
            .unwrap();

        // The caller (core) owns the bounded, re-validated redirect loop -
        // this client must hand back the raw 3xx untouched.
        assert_eq!(response.status, 302);
    }

    #[tokio::test]
    async fn test_fetch_auth_header_overrides_same_named_guest_header() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(MockMethod::GET)
                .path("/secure")
                .header("x-auth", "real-secret");
            then.status(200);
        });

        let fetcher = KeystoneDynamicPluginHttpFetcher::new();
        let mut guest_headers = HashMap::new();
        guest_headers.insert("X-Auth".to_string(), "guest-supplied".to_string());

        let response = fetcher
            .fetch(
                "GET",
                &format!("http://{}/secure", host_port(&server)),
                addr_of(&server),
                &guest_headers,
                None,
                5_000,
                Some(("X-Auth", "real-secret")),
                1_000_000,
            )
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        mock.assert();
    }

    #[tokio::test]
    async fn test_fetch_rejects_oversized_body_without_buffering_it_fully() {
        let server = MockServer::start();
        let big_body = "x".repeat(10_000);
        let _mock = server.mock(|when, then| {
            when.method(MockMethod::GET).path("/big");
            then.status(200).body(&big_body);
        });

        let fetcher = KeystoneDynamicPluginHttpFetcher::new();
        let err = fetcher
            .fetch(
                "GET",
                &format!("http://{}/big", host_port(&server)),
                addr_of(&server),
                &HashMap::new(),
                None,
                5_000,
                None,
                1_000,
            )
            .await
            .expect_err("a body exceeding max_body_bytes must be rejected");
        assert!(err.contains("exceed"));
    }

    #[tokio::test]
    async fn test_get_or_build_client_reuses_cached_client_for_same_addr_and_timeout() {
        let fetcher = KeystoneDynamicPluginHttpFetcher::new();
        let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();

        let c1 = fetcher
            .get_or_build_client("example.test", addr, 5_000)
            .unwrap();
        let c2 = fetcher
            .get_or_build_client("example.test", addr, 5_000)
            .unwrap();
        assert!(
            Arc::ptr_eq(&c1, &c2),
            "same (host, addr, timeout) should reuse the cached client"
        );
    }

    #[tokio::test]
    async fn test_get_or_build_client_rebuilds_on_address_change() {
        let fetcher = KeystoneDynamicPluginHttpFetcher::new();
        let addr1: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9443".parse().unwrap();

        let c1 = fetcher
            .get_or_build_client("example.test", addr1, 5_000)
            .unwrap();
        let c2 = fetcher
            .get_or_build_client("example.test", addr2, 5_000)
            .unwrap();
        assert!(
            !Arc::ptr_eq(&c1, &c2),
            "a changed resolved address must evict and rebuild, never reuse a stale pin"
        );
    }

    #[tokio::test]
    async fn test_get_or_build_client_rebuilds_on_timeout_change() {
        let fetcher = KeystoneDynamicPluginHttpFetcher::new();
        let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();

        let c1 = fetcher
            .get_or_build_client("example.test", addr, 5_000)
            .unwrap();
        let c2 = fetcher
            .get_or_build_client("example.test", addr, 9_000)
            .unwrap();
        assert!(!Arc::ptr_eq(&c1, &c2));
    }
}
