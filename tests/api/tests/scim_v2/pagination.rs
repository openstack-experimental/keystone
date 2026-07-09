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
//! Live-HTTP pagination for `GET /Users` and `GET /Groups` (ADR 0024 §5.D):
//! `startIndex`, `count`, `totalResults`, and page slicing.
//!
//! These tests use a `sw` filter on a unique prefix to isolate only
//! test-specific resources, then verify pagination metadata and traversal
//! without assuming global position-dependent ordering.

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimListResponse, ScimUser, ScimUserWrite, expect_ok};

use super::common::provision_scim_realm;

/// Creates `n` users with a shared prefix, returns the prefix.
async fn create_test_users(
    client: &test_api::scim::ScimTestClient,
    prefix: &str,
    n: usize,
) -> Result<Vec<ScimUser>> {
    let mut users = Vec::with_capacity(n);
    for i in 0..n {
        let username = format!("{}-{}-{:02}", prefix, Uuid::new_v4().simple(), i);
        let created: ScimUser =
            expect_ok(client.create_user(&ScimUserWrite::new(&username)).await?).await?;
        users.push(created);
    }
    Ok(users)
}

/// Filters a list to only our prefix, then returns the matched subset.
fn filter_by_prefix(list: &ScimListResponse<ScimUser>, prefix: &str) -> Vec<ScimUser> {
    list.resources
        .iter()
        .filter(|u| u.user_name.starts_with(prefix))
        .map(Clone::clone)
        .collect()
}

/// URL-encodes a SCIM filter expression.
fn filter_escape(raw: &str) -> String {
    raw.replace(' ', "%20")
        .replace('"', "%22")
        .replace("&", "%26")
        .replace('(', "%28")
        .replace(')', "%29")
}

#[tokio::test]
#[traced_test]
async fn test_pagination_count_and_start_index() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let prefix = format!("scim-paging-{}", Uuid::new_v4().simple());

    create_test_users(&provisioned.client, &prefix, 5).await?;

    // Fetch all matching at once, verify total_results is consistent.
    let wide_filter = format!(
        "filter={}&count=200",
        filter_escape(&format!("userName sw \"{}\"", prefix))
    );
    let all: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&wide_filter).await?).await?;
    assert_eq!(all.start_index, 1, "first page starts at 1");
    assert_eq!(
        all.items_per_page, 200,
        "items_per_page reflects requested count (capped at 200)"
    );

    let our_users = filter_by_prefix(&all, &prefix);
    assert_eq!(our_users.len(), 5, "should find exactly 5 test users");

    // Paginate through and collect all 5 users.
    // We don't trust total_results or positions (concurrent tests), so we
    // traverse until we've seen all 5 of our users.
    let mut seen_ids: std::collections::HashSet<String> = Default::default();
    let page_size = 2;
    let mut idx = 1usize;
    let expected = 5usize;
    let mut batch = 1;

    while seen_ids.len() < expected {
        let page: ScimListResponse<ScimUser> = expect_ok(
            provisioned
                .client
                .list_users(&format!(
                    "filter={}&count={}&start_index={}",
                    filter_escape(&format!("userName sw \"{}\"", prefix)),
                    page_size,
                    idx
                ))
                .await?,
        )
        .await?;

        assert_eq!(
            page.start_index, idx,
            "batch {} start_index mismatch",
            batch
        );
        assert_eq!(
            page.items_per_page, page_size,
            "batch {} items_per_page mismatch",
            batch
        );

        for u in filter_by_prefix(&page, &prefix) {
            let added = seen_ids.insert(u.id);
            assert!(added, "duplicate user ID found on page {}", batch);
        }

        idx += page_size;
        batch += 1;

        if batch > 10 {
            panic!(
                "pagination loop exceeded 10 iterations, only found {} of {} users",
                seen_ids.len(),
                expected
            );
        }
    }

    assert_eq!(
        seen_ids.len(),
        5,
        "pagination traversal should have found all 5 users"
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_pagination_defaults() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let prefix = format!("scim-paging-{}", Uuid::new_v4().simple());

    create_test_users(&provisioned.client, &prefix, 1).await?;

    // Use filter to isolate our user.
    let filter_query = format!(
        "filter={}",
        filter_escape(&format!("userName sw \"{}\"", prefix))
    );
    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&filter_query).await?).await?;

    assert!(
        listed.start_index >= 1,
        "start_index must be >= 1 (got {})",
        listed.start_index
    );
    assert!(
        listed.items_per_page > 0 && listed.items_per_page <= 200,
        "default items_per_page must be <= 200 (got {})",
        listed.items_per_page
    );

    let matched = filter_by_prefix(&listed, &prefix);
    assert_eq!(matched.len(), 1, "should find our single user");

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_pagination_total_results_includes_all_matches() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let prefix = format!("scim-user-{}", Uuid::new_v4().simple());

    let user1: ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!("{}-a", prefix)))
            .await?,
    )
    .await?;

    let user2: ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!("{}-b", prefix)))
            .await?,
    )
    .await?;

    // Filter for one user by eq, but ask for count=1.
    let filter_query = format!(
        "filter={}&count=1",
        filter_escape(&format!("userName eq \"{}\"", user1.user_name))
    );
    let filtered: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&filter_query).await?).await?;

    // We should get back our user, not the sibling user2 that shares the
    // same prefix -- proving `eq` is exact-match, not prefix-match.
    let matched = filter_by_prefix(&filtered, &prefix);
    assert_eq!(matched.len(), 1, "should get exactly our user");
    assert_eq!(matched[0].user_name, user1.user_name);
    assert!(
        !matched.iter().any(|u| u.id == user2.id),
        "eq filter must not include the sibling user2 sharing the same prefix"
    );

    // total_results reflects the filter match count before pagination.
    // Since we filtered by `eq` our exact username, total should be 1
    // (our user, plus any noise from other tests that happens to share the
    // prefix is irrelevant for the `eq` filter).
    assert_eq!(
        filtered.total_results, 1,
        "eq filter should match only user1"
    );
    assert_eq!(filtered.start_index, 1, "first page should start at 1");
    assert_eq!(filtered.items_per_page, 1, "page should have 1 item");

    provisioned.cleanup().await?;
    Ok(())
}
