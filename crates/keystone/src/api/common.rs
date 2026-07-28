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
use std::future::Future;
use std::net::SocketAddr;

use axum::{extract::FromRequestParts, http::Uri, http::request::Parts};
use url::{Url, form_urlencoded};

use openstack_keystone_api_types::{Link, PaginationQuery};
use openstack_keystone_config::{Config, ListLimitConfig};
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

/// Pagination controls, which a generated link replaces rather than inherits.
const PAGINATION_PARAMS: [&str; 3] = ["limit", "marker", "page_reverse"];

/// Build a single pagination `Link`, pointing `collection_url` at a new
/// `marker`/`page_reverse` combination derived from `query`.
///
/// Every **non-pagination** query parameter on `collection_url` is carried
/// over verbatim, so a filtered collection stays filtered across pages. Losing
/// them would silently widen the next page from, say,
/// `GET /v3/policies?type=application/json` to the unfiltered collection.
fn build_pagination_link(
    config: &Config,
    limit: u64,
    collection_url: &Uri,
    rel: &str,
    marker: String,
    page_reverse: bool,
) -> Result<Link, KeystoneApiError> {
    let mut url = if let Some(pe) = &config.default.public_endpoint {
        pe.clone()
    } else {
        Url::parse("http://localhost")?
    };
    url.set_path(collection_url.path());

    let new_query = PaginationQuery {
        limit: Some(limit),
        marker: Some(marker),
        page_reverse,
    };

    // Resource filters first, then the (authoritative) pagination controls.
    let mut serialized = String::new();
    for (key, value) in collection_url
        .query()
        .map(|q| form_urlencoded::parse(q.as_bytes()).collect::<Vec<_>>())
        .unwrap_or_default()
    {
        if PAGINATION_PARAMS.contains(&key.as_ref()) {
            continue;
        }
        if !serialized.is_empty() {
            serialized.push('&');
        }
        serialized.push_str(
            &form_urlencoded::Serializer::new(String::new())
                .append_pair(&key, &value)
                .finish(),
        );
    }
    let pagination = serde_urlencoded::to_string(&new_query)?;
    if !pagination.is_empty() {
        if !serialized.is_empty() {
            serialized.push('&');
        }
        serialized.push_str(&pagination);
    }
    url.set_query(Some(&serialized));

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

/// How many raw backend rows [`collect_authorized_page`] may examine per
/// request, as a multiple of the requested page size.
///
/// Bounds the cost of the per-item authorization refill loop. `2` means a
/// request for 10 items never inspects more than 20 rows, so a caller with
/// sparse visibility cannot turn one request into a full table scan.
pub const AUTHORIZED_PAGE_SCAN_FACTOR: u64 = 2;

/// Outcome of [`collect_authorized_page`].
#[derive(Debug)]
pub struct AuthorizedPage<T> {
    /// The authorized items, up to `limit + 1` of them.
    pub items: Vec<T>,
    /// `true` when the scan stopped because the examine budget ran out, rather
    /// than because the page filled or the backend was exhausted. More visible
    /// rows may remain even when `items` is shorter than the page size.
    pub scan_budget_exhausted: bool,
}

/// Fill a page with items the caller is actually allowed to see.
///
/// A list endpoint that re-checks every item against the per-item read policy
/// (security model I8) cannot just over-fetch `limit + 1` rows once: if any of
/// them are filtered out, the surviving count can drop to `limit` or below
/// while more *visible* rows still exist. [`paginate_forward`] then reads that
/// as "no next page" and pagination stops early, silently hiding the tail of
/// the collection.
///
/// This keeps pulling backend batches — advancing the marker past the last
/// **raw** row of each batch, authorized or not — until `limit + 1` authorized
/// items are collected, the backend runs out, or the scan budget is spent. The
/// `limit + 1`th item is the over-fetch sentinel [`paginate_forward`] expects.
///
/// # Scan budget
///
/// Refilling is bounded: at most `limit * `[`AUTHORIZED_PAGE_SCAN_FACTOR`] raw
/// rows are examined per request. Without a bound, a caller who may read only a
/// sparse subset of a large collection would walk the entire table on every
/// request — a cheap way to force a full scan. When the budget is spent before
/// the page fills, [`AuthorizedPage::scan_budget_exhausted`] is set so the
/// caller can still advertise a `next` link (see
/// [`paginate_forward_filtered`]) instead of reporting a short page as the end
/// of the collection.
///
/// `authorize` takes ownership and returns `Ok(None)` to drop an item; any
/// `Err` is propagated, so a policy-engine failure fails the request instead of
/// being mistaken for a denial.
pub async fn collect_authorized_page<T, Fetch, FetchFut, Authorize, AuthorizeFut>(
    limit: Option<u64>,
    initial_marker: Option<String>,
    mut fetch: Fetch,
    mut authorize: Authorize,
) -> Result<AuthorizedPage<T>, KeystoneApiError>
where
    T: ResourceIdentifier,
    Fetch: FnMut(Option<String>) -> FetchFut,
    FetchFut: Future<Output = Result<Vec<T>, KeystoneApiError>>,
    Authorize: FnMut(T) -> AuthorizeFut,
    AuthorizeFut: Future<Output = Result<Option<T>, KeystoneApiError>>,
{
    let Some(limit) = limit else {
        // Unpaginated: a single batch is the whole collection, so there is no
        // page to refill and no budget to spend.
        let raw = fetch(initial_marker).await?;
        let mut items = Vec::with_capacity(raw.len());
        for item in raw {
            if let Some(item) = authorize(item).await? {
                items.push(item);
            }
        }
        return Ok(AuthorizedPage {
            items,
            scan_budget_exhausted: false,
        });
    };

    // One past `limit` so `paginate_forward` can tell "there is a next page"
    // exactly rather than guessing.
    let wanted = limit as usize + 1;
    // Never below `wanted`, or a single batch could not even be consumed.
    let budget = limit
        .saturating_mul(AUTHORIZED_PAGE_SCAN_FACTOR)
        .max(wanted as u64) as usize;

    let mut items: Vec<T> = Vec::with_capacity(wanted);
    let mut examined = 0usize;
    let mut marker = initial_marker;

    loop {
        let raw = fetch(marker.clone()).await?;
        let fetched = raw.len();
        let Some(last_raw_id) = raw.last().map(ResourceIdentifier::get_id) else {
            break;
        };

        for item in raw {
            examined += 1;
            if let Some(item) = authorize(item).await? {
                items.push(item);
                if items.len() >= wanted {
                    return Ok(AuthorizedPage {
                        items,
                        scan_budget_exhausted: false,
                    });
                }
            }
            if examined >= budget {
                // Out of budget with the page unfilled: report it so the
                // caller advertises a `next` link rather than presenting a
                // short page as the end of the collection.
                return Ok(AuthorizedPage {
                    items,
                    scan_budget_exhausted: true,
                });
            }
        }

        // The backend also over-fetches by one, so a batch smaller than
        // `wanted` means it has nothing left behind this one.
        if fetched < wanted {
            break;
        }
        marker = Some(last_raw_id);
    }

    Ok(AuthorizedPage {
        items,
        scan_budget_exhausted: false,
    })
}

/// [`paginate_forward`] for a page produced by [`collect_authorized_page`].
///
/// Adds one thing the plain paginator cannot know: when the refill loop stopped
/// on its scan budget, the page can be *shorter* than the limit while more
/// visible rows still exist. Reporting that as the end of the collection is the
/// very truncation bug the refill loop exists to fix, so a `next` link is
/// emitted anyway, keyed on the last authorized item.
///
/// If the budget ran out before a single authorized item was found there is no
/// safe marker to hand back — the last row examined belongs to an object the
/// caller may not read, and putting its ID in a link would disclose it — so no
/// link is emitted and the truncation is logged. A caller in that position is
/// one whose visible rows are sparser than the entire budget window.
pub fn paginate_forward_filtered<T: ResourceIdentifier>(
    config: &Config,
    provider_limit: &ListLimitConfig,
    page: AuthorizedPage<T>,
    query: &PaginationQuery,
    collection_url: &Uri,
) -> Result<(Vec<T>, Option<Vec<Link>>), KeystoneApiError> {
    let AuthorizedPage {
        items,
        scan_budget_exhausted,
    } = page;

    let (items, links) = paginate_forward(config, provider_limit, items, query, collection_url)?;

    if !scan_budget_exhausted || links.is_some() {
        return Ok((items, links));
    }

    let Some(last) = items.last() else {
        tracing::warn!(
            "per-item authorization scan budget exhausted with no authorized \
             rows; the response may omit visible entries beyond this point"
        );
        return Ok((items, None));
    };

    let limit = config
        .resolve_list_limit(provider_limit, query.limit)
        .unwrap_or_default();
    let link = build_pagination_link(config, limit, collection_url, "next", last.get_id(), false)?;
    Ok((items, Some(vec![link])))
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
    provider_limit: &ListLimitConfig,
    mut items: Vec<T>,
    query: &PaginationQuery,
    collection_url: &Uri,
) -> Result<(Vec<T>, Option<Vec<Link>>), KeystoneApiError> {
    // Resolve the limit here rather than trusting `query.limit`: the handler
    // fetched `effective + 1` rows, so slicing and link generation must use
    // that same effective value. Reading the raw client value instead let a
    // request over `max_list_limit` return more rows than the cap allows and
    // suppressed its `next` link.
    let Some(limit) = config.resolve_list_limit(provider_limit, query.limit) else {
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
                build_pagination_link(config, limit, collection_url, "next", last.get_id(), false)
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
    provider_limit: &ListLimitConfig,
    mut items: Vec<T>,
    query: &PaginationQuery,
    collection_url: &Uri,
) -> Result<(Vec<T>, Option<Vec<Link>>), KeystoneApiError> {
    // See `paginate_forward`: the effective limit, not the raw client value.
    let Some(limit) = config.resolve_list_limit(provider_limit, query.limit) else {
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
                limit,
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
                limit,
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
                limit,
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
                limit,
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
    use std::cell::Cell;
    use std::rc::Rc;

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

    /// Fetch `all[start..]` in fixed-size batches, counting calls.
    ///
    /// The counter is shared through an `Rc` so the returned closure can *own*
    /// its handle. Taking `&Cell` instead would tie the closure to that
    /// borrow's lifetime, which the `impl FnMut` return type cannot name.
    fn batched_fetch(
        all: &[&'static str],
        batch: usize,
        calls: Rc<Cell<usize>>,
    ) -> impl FnMut(Option<String>) -> std::future::Ready<Result<Vec<FakeResource>, KeystoneApiError>>
    {
        let all: Vec<String> = all.iter().map(|s| (*s).to_string()).collect();
        move |marker| {
            calls.set(calls.get() + 1);
            let start = match &marker {
                None => 0,
                Some(m) => all.iter().position(|id| id == m).map_or(0, |i| i + 1),
            };
            let rows = all
                .iter()
                .skip(start)
                .take(batch)
                .map(|id| FakeResource { id: id.clone() })
                .collect();
            std::future::ready(Ok(rows))
        }
    }

    fn allow_except(
        denied: &'static [&'static str],
    ) -> impl FnMut(FakeResource) -> std::future::Ready<Result<Option<FakeResource>, KeystoneApiError>>
    {
        move |item: FakeResource| {
            std::future::ready(Ok(if denied.contains(&item.id.as_str()) {
                None
            } else {
                Some(item)
            }))
        }
    }

    /// `collect_authorized_page` keeps pulling batches until it has `limit + 1`
    /// *authorized* items, so denied rows cannot truncate pagination. Without
    /// the refill loop this returned a short page and no `next` link, stranding
    /// the visible rows behind the denied ones.
    #[tokio::test]
    async fn test_collect_authorized_page_refills_past_denied_items() {
        const ALL: &[&str] = &["1", "2", "3", "4", "5", "6", "7", "8", "9"];
        let calls = Rc::new(Cell::new(0usize));

        // limit 2 -> wants 3, budget 4. Row "1" is denied, so the first batch
        // of 3 yields only 2 authorized items and a second batch is needed.
        let page = collect_authorized_page(
            Some(2),
            None,
            batched_fetch(ALL, 3, calls.clone()),
            allow_except(&["1"]),
        )
        .await
        .unwrap();

        assert_eq!(
            page.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["2", "3", "4"],
            "must refill to limit + 1 authorized items across batches"
        );
        assert!(!page.scan_budget_exhausted);
        assert_eq!(calls.get(), 2, "the denied row forced exactly one refill");
    }

    /// Reviewer corner case: *every* row the backend returns is rejected. The
    /// page is empty and the scan is reported as budget-limited rather than as
    /// a genuine end-of-collection.
    #[tokio::test]
    async fn test_collect_authorized_page_all_rows_denied() {
        const ALL: &[&str] = &["1", "2", "3", "4", "5", "6", "7", "8"];
        let calls = Rc::new(Cell::new(0usize));

        let page = collect_authorized_page(
            Some(2),
            None,
            batched_fetch(ALL, 3, calls.clone()),
            allow_except(&["1", "2", "3", "4", "5", "6", "7", "8"]),
        )
        .await
        .unwrap();

        assert!(page.items.is_empty(), "nothing is authorized");
        assert!(
            page.scan_budget_exhausted,
            "an all-denied scan must not look like the end of the collection"
        );
    }

    /// Reviewer corner case: the second batch comes back *shorter* than
    /// requested, which means the backend is exhausted — the loop must abort
    /// rather than keep re-fetching.
    #[tokio::test]
    async fn test_collect_authorized_page_aborts_when_second_batch_is_short() {
        const ALL: &[&str] = &["1", "2", "3", "4"];
        let calls = Rc::new(Cell::new(0usize));

        // limit 3 -> wants 4, batch 4: first batch returns 4 (== wanted, so
        // "maybe more"), second returns 0 and ends the loop.
        let page = collect_authorized_page(
            Some(3),
            None,
            batched_fetch(ALL, 4, calls.clone()),
            allow_except(&["1"]),
        )
        .await
        .unwrap();

        assert_eq!(
            page.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["2", "3", "4"],
            "only the authorized rows, and fewer than the page size"
        );
        assert!(
            !page.scan_budget_exhausted,
            "the backend really is exhausted, so this is a true final page"
        );
        assert_eq!(calls.get(), 2, "one refill, then the empty batch stops it");
    }

    /// Reviewer corner case: every batch comes back *exactly* `limit + 1` long,
    /// so "maybe more" is always true. The budget — not the data — must end the
    /// loop, and it must do so after a bounded number of rows.
    #[tokio::test]
    async fn test_collect_authorized_page_budget_stops_endless_refill() {
        const ALL: &[&str] = &[
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
        ];
        let calls = Rc::new(Cell::new(0usize));
        let examined = Cell::new(0usize);

        let limit = 3u64;
        let page = collect_authorized_page(
            Some(limit),
            None,
            batched_fetch(ALL, limit as usize + 1, calls.clone()),
            |_item: FakeResource| {
                examined.set(examined.get() + 1);
                // Deny everything, so only the budget can end the loop.
                std::future::ready(Ok(None))
            },
        )
        .await
        .unwrap();

        assert!(page.items.is_empty());
        assert!(page.scan_budget_exhausted, "the budget must stop the loop");
        let budget = (limit * AUTHORIZED_PAGE_SCAN_FACTOR) as usize;
        assert_eq!(
            examined.get(),
            budget,
            "must examine exactly the budget, never the whole table"
        );
        assert!(
            examined.get() < ALL.len(),
            "a full table scan is what the budget prevents"
        );
    }

    /// A budget-truncated short page still advertises a `next` link, keyed on
    /// the last authorized item — otherwise the caller would treat the short
    /// page as the end of the collection.
    #[test]
    fn test_paginate_forward_filtered_links_after_budget_truncation() {
        let page = AuthorizedPage {
            items: fake_items(2),
            scan_budget_exhausted: true,
        };
        let (items, links) = paginate_forward_filtered(
            &Config::default(),
            &ListLimitConfig {
                list_limit: None,
                max_list_limit: Some(10),
            },
            page,
            &PaginationQuery {
                limit: Some(10),
                ..Default::default()
            },
            &"/v3/credentials?type=ec2&limit=10".parse::<Uri>().unwrap(),
        )
        .unwrap();

        assert_eq!(items.len(), 2, "the short page is returned as-is");
        let href = &links.expect("a next link is required")[0].href;
        // `fake_items` is 0-indexed, so the last of two items is "1".
        assert!(
            href.contains("marker=1"),
            "keyed on the last authorized item: {href}"
        );
        assert!(href.contains("type=ec2"), "filter preserved: {href}");
    }

    /// With no authorized item there is no marker that does not disclose an
    /// object the caller may not read, so no link is emitted.
    #[test]
    fn test_paginate_forward_filtered_no_link_without_authorized_items() {
        let page: AuthorizedPage<FakeResource> = AuthorizedPage {
            items: Vec::new(),
            scan_budget_exhausted: true,
        };
        let (items, links) = paginate_forward_filtered(
            &Config::default(),
            &ListLimitConfig::default(),
            page,
            &PaginationQuery {
                limit: Some(5),
                ..Default::default()
            },
            &"/v3/credentials".parse::<Uri>().unwrap(),
        )
        .unwrap();

        assert!(items.is_empty());
        assert_eq!(links, None, "no marker can be published safely");
    }

    /// With no `?limit` and no configuration, nothing is truncated and no
    /// links are emitted — matching python keystone, whose `[DEFAULT]
    /// list_limit` is unset out of the box.
    #[test]
    fn test_paginate_forward_unlimited_by_default() {
        let query = PaginationQuery::default();
        assert_eq!(
            query.limit, None,
            "the serde default must not inject a page size"
        );

        let (items, links) = paginate_forward(
            &Config::default(),
            &ListLimitConfig::default(),
            fake_items(50),
            &query,
            &"/foo/bar".parse::<Uri>().unwrap(),
        )
        .unwrap();

        assert_eq!(items.len(), 50);
        assert_eq!(links, None);
    }

    /// A per-provider `list_limit` governs the page size when the client
    /// omits `limit`. Before the effective-limit fix the serde default of
    /// `Some(20)` shadowed `requested`, so this setting was dead config.
    #[test]
    fn test_paginate_forward_uses_provider_default_limit() {
        let provider_limit = ListLimitConfig {
            list_limit: Some(2),
            max_list_limit: None,
        };
        // The backend over-fetches `limit + 1`.
        let (items, links) = paginate_forward(
            &Config::default(),
            &provider_limit,
            fake_items(3),
            &PaginationQuery::default(),
            &"/foo/bar".parse::<Uri>().unwrap(),
        )
        .unwrap();

        assert_eq!(items.len(), 2, "page must honour the configured list_limit");
        assert!(links.is_some(), "a next link is required");
    }

    /// A client `limit` above `max_list_limit` is clamped, and the clamp
    /// governs both the slice and the link. Reading the raw client value
    /// returned more rows than the cap and suppressed the `next` link.
    #[test]
    fn test_paginate_forward_clamps_to_max_list_limit() {
        let provider_limit = ListLimitConfig {
            list_limit: None,
            max_list_limit: Some(10),
        };
        let query = PaginationQuery {
            limit: Some(100),
            ..Default::default()
        };

        // The handler resolved the same effective limit (10) and fetched 11.
        let (items, links) = paginate_forward(
            &Config::default(),
            &provider_limit,
            fake_items(11),
            &query,
            &"/foo/bar".parse::<Uri>().unwrap(),
        )
        .unwrap();

        assert_eq!(items.len(), 10, "must not exceed max_list_limit");
        let links = links.expect("a next link is required when rows remain");
        assert!(
            links[0].href.contains("limit=10"),
            "the link must advertise the clamped limit, not the request's 100: {}",
            links[0].href
        );
    }

    /// Resource filters survive into the next link *and* coexist with the
    /// clamped pagination controls.
    #[test]
    fn test_paginate_forward_link_keeps_filters_with_effective_limit() {
        let provider_limit = ListLimitConfig {
            list_limit: None,
            max_list_limit: Some(2),
        };
        let query = PaginationQuery {
            limit: Some(50),
            ..Default::default()
        };

        let (_, links) = paginate_forward(
            &Config::default(),
            &provider_limit,
            fake_items(3),
            &query,
            &"/v3/policies?type=application%2Fjson&limit=50"
                .parse::<Uri>()
                .unwrap(),
        )
        .unwrap();

        let href = &links.expect("next link")[0].href;
        assert!(
            href.contains("type=application%2Fjson"),
            "filter kept: {href}"
        );
        assert!(href.contains("limit=2"), "clamped limit: {href}");
        assert_eq!(
            href.matches("limit=").count(),
            1,
            "no duplicate limit: {href}"
        );
        assert!(href.contains("marker="), "marker present: {href}");
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
        let (items, links) = paginate_forward(
            &Config::default(),
            &ListLimitConfig::default(),
            fake_items(cnt),
            &query,
            &"/foo/bar".parse::<Uri>().unwrap(),
        )
        .unwrap();
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
        let (items, links) = paginate_bidirectional(
            &Config::default(),
            &ListLimitConfig::default(),
            fake_items(cnt),
            &query,
            &"/foo/bar".parse::<Uri>().unwrap(),
        )
        .unwrap();
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
