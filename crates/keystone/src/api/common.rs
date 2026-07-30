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
//! # Common API helpers
use std::net::SocketAddr;

use axum::{extract::FromRequestParts, http::request::Parts};
use url::Url;

use openstack_keystone_api_types::{Link, PaginationQuery};
use openstack_keystone_config::Config;
use openstack_keystone_core::net::public_ingress_peer_addr;
use openstack_keystone_core_types::resource::Domain;

use crate::api::KeystoneApiError;
use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;

// Canonical header name for proxy-forwarded protocol.
const FORWARDED_PROTO: &str = "x-forwarded-proto";

/// Raw TCP peer address for the public interface only.
///
/// Internal/admin requests return `None` even when `ConnectInfo` is populated
/// for audit logging. If proxy middleware rewrote `ConnectInfo`, the preserved
/// original peer is returned so each security control applies its own trust
/// boundary.
pub struct PeerAddr(pub Option<SocketAddr>);

impl<S: Send + Sync> FromRequestParts<S> for PeerAddr {
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(PeerAddr(public_ingress_peer_addr(&parts.extensions)))
    }
}

/// Resolve the public-facing base URL for constructing absolute links
/// in API responses.
///
/// Fallback chain:
/// 1. `public_endpoint` from config
/// 2. `Host` header with protocol derived from `X-Forwarded-Proto` when
///    `[oslo_middleware] enable_proxy_headers_parsing` is true; otherwise
///    defaults to `http`.
/// 3. `http://localhost` as last resort
pub async fn public_base_url(state: &ServiceState, headers: &axum::http::HeaderMap) -> String {
    let config = state.config_manager.config.read().await;
    let proxy_headers_enabled = config.oslo_middleware.enable_proxy_headers_parsing;
    drop(config);

    state
        .config_manager
        .config
        .read()
        .await
        .default
        .public_endpoint
        .clone()
        .map(|x| x.to_string())
        .or_else(|| {
            headers.get(axum::http::header::HOST).and_then(|host| {
                host.to_str().ok().map(|h| {
                    let proto = if proxy_headers_enabled {
                        headers
                            .get(FORWARDED_PROTO)
                            .and_then(|h| h.to_str().ok())
                            .filter(|v| matches!(*v, "http" | "https"))
                            .unwrap_or("http")
                    } else {
                        // When proxy headers are not enabled, never trust the
                        // forwarded-protocol header — it could be spoofed by any
                        // client reaching the listener directly.
                        "http"
                    };
                    format!("{proto}://{h}")
                })
            })
        })
        .unwrap_or_else(|| "http://localhost".to_string())
}

/// Returns true when the request arrived over HTTPS as indicated by the
/// `X-Forwarded-Proto` header being set to `https`.
///
/// Only returns `true` when `[oslo_middleware] enable_proxy_headers_parsing` is
/// enabled; otherwise always returns `false` to prevent arbitrary clients from
/// spoofing HTTPS status.
pub async fn is_https(state: &ServiceState, headers: &axum::http::HeaderMap) -> bool {
    let proxy_headers_enabled = state
        .config_manager
        .config
        .read()
        .await
        .oslo_middleware
        .enable_proxy_headers_parsing;
    if !proxy_headers_enabled {
        return false;
    }
    headers.get(FORWARDED_PROTO).and_then(|h| h.to_str().ok()) == Some("https")
}

/// Get the domain by ID or Name.
///
/// # Arguments
/// * `state` - The service state
/// * `id` - The domain ID
/// * `name` - The domain name
///
/// # Returns
/// * `Result<Domain, KeystoneApiError>` - The domain object
// Not yet wired into an endpoint (no id-or-name domain lookup route exists
// yet); kept for the domain-scoped auth work it was written for.
#[allow(dead_code)]
pub async fn get_domain<I: AsRef<str>, N: AsRef<str>>(
    state: &ServiceState,
    id: Option<I>,
    name: Option<N>,
) -> Result<Domain, KeystoneApiError> {
    let exec = ExecutionContext::internal(state);
    if let Some(did) = &id {
        state
            .provider
            .get_resource_provider()
            .get_domain(&exec, did.as_ref())
            .await?
            .ok_or_else(|| KeystoneApiError::NotFound {
                resource: "domain".into(),
                identifier: did.as_ref().to_string(),
            })
    } else if let Some(name) = &name {
        state
            .provider
            .get_resource_provider()
            .find_domain_by_name(&exec, name.as_ref())
            .await?
            .ok_or_else(|| KeystoneApiError::NotFound {
                resource: "domain".into(),
                identifier: name.as_ref().to_string(),
            })
    } else {
        Err(KeystoneApiError::DomainIdOrName)
    }
}

/// Trait for the resource to expose the unique identifier that can be used for
/// building the marker pagination.
pub trait ResourceIdentifier {
    /// Get the unique resource identifier.
    fn get_id(&self) -> String;
}

/// Build a single pagination `Link`, pointing `collection_url` at a new
/// `marker`/`page_reverse` combination derived from `query`.
fn build_pagination_link(
    config: &Config,
    query: &PaginationQuery,
    collection_url: &str,
    rel: &str,
    marker: String,
    page_reverse: bool,
) -> Result<Link, KeystoneApiError> {
    let mut url = if let Some(pe) = &config.default.public_endpoint {
        pe.clone()
    } else {
        Url::parse("http://localhost")?
    };
    url.set_path(collection_url);

    let new_query = PaginationQuery {
        limit: query.limit,
        marker: Some(marker),
        page_reverse,
    };
    url.set_query(Some(&serde_urlencoded::to_string(&new_query)?));

    let href = format!(
        "{}{}",
        url.path(),
        url.query().map(|q| format!("?{}", q)).unwrap_or_default()
    );
    Ok(Link {
        rel: rel.to_string(),
        href,
    })
}

/// Paginate a forward-only (v3, python-keystone compatible) list response.
///
/// The backend is expected to have over-fetched by one row (`limit + 1`) so
/// that "is there a next page" can be answered exactly instead of
/// heuristically guessing from `returned_count >= limit` (which produces a
/// false-positive `next` link when the table has exactly `limit` rows left).
/// This trims the extra row off before returning the page.
///
/// Never emits a `previous` link — v3 stays forward-only to match real
/// python-keystone behavior (its `previous` is always `null`).
pub fn paginate_forward<T: ResourceIdentifier>(
    config: &Config,
    mut items: Vec<T>,
    query: &PaginationQuery,
    collection_url: &str,
) -> Result<(Vec<T>, Option<Vec<Link>>), KeystoneApiError> {
    let Some(limit) = query.limit else {
        return Ok((items, None));
    };

    let has_next = items.len() as u64 > limit;
    if has_next {
        items.truncate(limit as usize);
    }

    let links = if has_next {
        items
            .last()
            .map(|last| {
                build_pagination_link(config, query, collection_url, "next", last.get_id(), false)
            })
            .transpose()?
            .map(|link| vec![link])
    } else {
        None
    };

    Ok((items, links))
}

/// Paginate a bidirectional (v4) list response.
///
/// Same over-fetch/trim mechanism as [`paginate_forward`], but also builds a
/// `previous` link. The backend is expected to fetch `limit + 1` rows in the
/// direction implied by `query.page_reverse`:
/// - forward (`page_reverse == false`): ascending, after `marker`. The extra
///   row (if any) is trimmed off the tail and signals `next`.
/// - backward (`page_reverse == true`): descending, before `marker`, then
///   re-sorted ascending before being passed in here. The extra row (if any) is
///   trimmed off the *head* and signals `previous`.
///
/// Going forward from a backward page is always possible by re-requesting
/// the original `marker` with `page_reverse: false` — no extra lookup needed.
pub fn paginate_bidirectional<T: ResourceIdentifier>(
    config: &Config,
    mut items: Vec<T>,
    query: &PaginationQuery,
    collection_url: &str,
) -> Result<(Vec<T>, Option<Vec<Link>>), KeystoneApiError> {
    let Some(limit) = query.limit else {
        return Ok((items, None));
    };

    let mut links = Vec::new();

    if query.page_reverse {
        // We fetched backward; the truncation edge (if any) is at the head.
        let has_previous = items.len() as u64 > limit;
        if has_previous {
            items = items.split_off(items.len() - limit as usize);
        }
        if has_previous && let Some(first) = items.first() {
            links.push(build_pagination_link(
                config,
                query,
                collection_url,
                "previous",
                first.get_id(),
                true,
            )?);
        }
        // The page you'd get by going forward from here is exactly the page
        // reached by re-requesting the marker that got us here, forward.
        if let Some(marker) = &query.marker {
            links.push(build_pagination_link(
                config,
                query,
                collection_url,
                "next",
                marker.clone(),
                false,
            )?);
        }
    } else {
        let has_next = items.len() as u64 > limit;
        if has_next {
            items.truncate(limit as usize);
        }
        if has_next && let Some(last) = items.last() {
            links.push(build_pagination_link(
                config,
                query,
                collection_url,
                "next",
                last.get_id(),
                false,
            )?);
        }
        // Only offer `previous` once we've actually moved past the first page.
        if query.marker.is_some()
            && let Some(first) = items.first()
        {
            links.push(build_pagination_link(
                config,
                query,
                collection_url,
                "previous",
                first.get_id(),
                true,
            )?);
        }
    }

    Ok((items, if links.is_empty() { None } else { Some(links) }))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::resource::Domain;

    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[tokio::test]
    async fn test_get_domain() {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_exec, id: &'_ str| id == "domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "domain_id".into(),
                    name: "domain_name".into(),
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_find_domain_by_name()
            .withf(|_exec, id: &'_ str| id == "domain_name")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "domain_id".into(),
                    name: "domain_name".into(),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_resource(resource_mock),
            true,
            None,
        )
        .await;

        assert_eq!(
            "domain_id",
            get_domain(&state, Some("domain_id"), None::<&str>)
                .await
                .unwrap()
                .id
        );
        assert_eq!(
            "domain_id",
            get_domain(&state, None::<&str>, Some("domain_name"))
                .await
                .unwrap()
                .id
        );
        assert_eq!(
            "domain_id",
            get_domain(&state, Some("domain_id"), Some("other_domain_name"))
                .await
                .unwrap()
                .id
        );
        match get_domain(&state, None::<&str>, None::<&str>).await {
            Err(KeystoneApiError::DomainIdOrName) => {}
            _ => {
                panic!("wrong result");
            }
        }
    }

    /// Fake resource for pagination testing.
    struct FakeResource {
        pub id: String,
    }

    impl ResourceIdentifier for FakeResource {
        fn get_id(&self) -> String {
            self.id.clone()
        }
    }

    fn fake_items(cnt: usize) -> Vec<FakeResource> {
        Vec::from_iter((0..cnt).map(|x| FakeResource { id: x.to_string() }))
    }

    fn pq(limit: Option<u64>, marker: Option<&str>, page_reverse: bool) -> PaginationQuery {
        PaginationQuery {
            limit,
            marker: marker.map(String::from),
            page_reverse,
        }
    }

    /// `cnt` simulates a backend that over-fetches by one row: passing
    /// exactly `limit` items means "no more pages" (the false-positive case
    /// this design fixes); passing `limit + 1` means "there is a next page".
    #[rstest]
    #[case(5, pq(None, Some("x"), false), 5, None)]
    #[case(5, pq(Some(5), Some("x"), false), 5, None)] // exact count: no false-positive next
    #[case(6, pq(Some(5), Some("x"), false), 5, Some(vec![
        Link { rel: "next".into(), href: "/foo/bar?limit=5&marker=4".into() }
    ]))]
    #[case(4, pq(Some(3), Some("x"), false), 3, Some(vec![
        Link { rel: "next".into(), href: "/foo/bar?limit=3&marker=2".into() }
    ]))]
    #[case(2, pq(Some(1), Some("x"), false), 1, Some(vec![
        Link { rel: "next".into(), href: "/foo/bar?limit=1&marker=0".into() }
    ]))]
    #[case(1, pq(Some(0), Some("x"), false), 0, None)] // truncated to empty: no sensible marker
    #[case(0, pq(Some(6), Some("x"), false), 0, None)]
    #[case(0, pq(Some(6), None, false), 0, None)]
    #[case(6, pq(Some(5), None, false), 5, Some(vec![
        Link { rel: "next".into(), href: "/foo/bar?limit=5&marker=4".into() }
    ]))]
    fn test_paginate_forward(
        #[case] cnt: usize,
        #[case] query: PaginationQuery,
        #[case] expected_len: usize,
        #[case] expected_links: Option<Vec<Link>>,
    ) {
        let (items, links) =
            paginate_forward(&Config::default(), fake_items(cnt), &query, "foo/bar").unwrap();
        assert_eq!(items.len(), expected_len);
        assert_eq!(links, expected_links);
    }

    #[rstest]
    // forward, more remaining, had a marker already (not first page): next + previous
    #[case(6, pq(Some(5), Some("x"), false), 5, Some(vec![
        Link { rel: "next".into(), href: "/foo/bar?limit=5&marker=4".into() },
        Link { rel: "previous".into(), href: "/foo/bar?limit=5&marker=0&page_reverse=true".into() },
    ]))]
    // forward, more remaining, first page (no marker yet): next only
    #[case(6, pq(Some(5), None, false), 5, Some(vec![
        Link { rel: "next".into(), href: "/foo/bar?limit=5&marker=4".into() },
    ]))]
    // forward, exact count (no more), not first page: previous only
    #[case(5, pq(Some(5), Some("x"), false), 5, Some(vec![
        Link { rel: "previous".into(), href: "/foo/bar?limit=5&marker=0&page_reverse=true".into() },
    ]))]
    // backward, more before, has an anchor marker: previous + next (back to where we came from)
    #[case(6, pq(Some(5), Some("m"), true), 5, Some(vec![
        Link { rel: "previous".into(), href: "/foo/bar?limit=5&marker=1&page_reverse=true".into() },
        Link { rel: "next".into(), href: "/foo/bar?limit=5&marker=m".into() },
    ]))]
    // backward, exact count (no more before): next only
    #[case(5, pq(Some(5), Some("m"), true), 5, Some(vec![
        Link { rel: "next".into(), href: "/foo/bar?limit=5&marker=m".into() },
    ]))]
    fn test_paginate_bidirectional(
        #[case] cnt: usize,
        #[case] query: PaginationQuery,
        #[case] expected_len: usize,
        #[case] expected_links: Option<Vec<Link>>,
    ) {
        let (items, links) =
            paginate_bidirectional(&Config::default(), fake_items(cnt), &query, "foo/bar").unwrap();
        assert_eq!(items.len(), expected_len);
        assert_eq!(links, expected_links);
    }

    #[rstest]
    #[case("https", true)]
    #[case("http", false)]
    #[case("gre", false)]
    #[tokio::test]
    async fn test_is_https(#[case] header_value: &str, #[case] _expected: bool) {
        let mut headers = axum::http::HeaderMap::new();
        if let Ok(hv) = header_value.parse::<axum::http::HeaderValue>() {
            let _ = headers.insert(FORWARDED_PROTO, hv);
        }
        // `get_mocked_state` uses default config where
        // `enable_proxy_headers_parsing` is false, so `is_https`
        // always returns false.
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        assert!(!is_https(&state, &headers).await);
    }

    #[rstest]
    #[case(None, None, "http://localhost")]
    #[case(Some("api.example.com"), None, "http://api.example.com")]
    #[case(Some("api.example.com"), Some("https"), "http://api.example.com")] // proxy headers disabled, so X-Forwarded-Proto is ignored
    #[case(Some("api.example.com"), Some("http"), "http://api.example.com")]
    #[case(
        Some("api.example.com:5000"),
        Some("https"),
        "http://api.example.com:5000"
    )] // proxy headers disabled
    #[case(Some("api.example.com"), Some("gre"), "http://api.example.com")] // proxy headers disabled
    #[tokio::test]
    async fn test_public_base_url_with_proxy_headers_disabled(
        #[case] host: Option<&str>,
        #[case] forwarded_proto: Option<&str>,
        #[case] expected: &str,
    ) {
        let mut headers = axum::http::HeaderMap::new();
        if let Some(h) = host
            && let Ok(hv) = h.parse::<axum::http::HeaderValue>()
        {
            let _ = headers.insert(axum::http::header::HOST, hv);
        }
        if let Some(p) = forwarded_proto
            && let Ok(pv) = p.parse::<axum::http::HeaderValue>()
        {
            let _ = headers.insert(FORWARDED_PROTO, pv);
        }
        // get_mocked_state uses Config::default() with proxy headers
        // disabled, so the forwarded-protocol header is never trusted.
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        assert_eq!(public_base_url(&state, &headers).await, expected);
    }
}
