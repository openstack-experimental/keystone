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
//! Live-HTTP filter operators beyond `eq`: `ne`, `co`, `sw`, `pr`,
//! boolean `and`/`or` chains, and disallow checks.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimListResponse, ScimUser, ScimUserWrite, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_filter_ne_operator() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let u1 = format!("scim-user-{}", Uuid::new_v4().simple());
    let u2 = format!("scim-user-{}", Uuid::new_v4().simple());

    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u1))
            .await?,
    )
    .await?;
    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u2))
            .await?,
    )
    .await?;

    // ne should return the other user, excluding u1.
    let query = format!(
        "filter={}",
        filter_escape(&format!(r#"userName ne "{u1}""#))
    );
    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&query).await?).await?;
    assert_eq!(listed.total_results, 1);
    assert_eq!(listed.resources[0].user_name, u2);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_filter_co_contains_operator() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let u1 = format!("scim-prefix-{}", Uuid::new_v4().simple());
    let u2 = format!("scim-other-{}", Uuid::new_v4().simple());

    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u1))
            .await?,
    )
    .await?;
    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u2))
            .await?,
    )
    .await?;

    // `co` matches a substring anywhere in the value.
    let query = format!("filter={}", filter_escape(r#"userName co "prefix""#));
    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&query).await?).await?;
    assert_eq!(listed.total_results, 1);
    assert_eq!(listed.resources[0].user_name, u1);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_filter_sw_starts_with_operator() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let u1 = format!("scim-alpha-{}", Uuid::new_v4().simple());
    let u2 = format!("scim-beta-{}", Uuid::new_v4().simple());

    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u1))
            .await?,
    )
    .await?;
    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u2))
            .await?,
    )
    .await?;

    let query = format!("filter={}", filter_escape(r#"userName sw "scim-alpha""#));
    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&query).await?).await?;
    assert_eq!(listed.total_results, 1);
    assert_eq!(listed.resources[0].user_name, u1);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_filter_pr_present_operator() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let u1 = format!("scim-user-{}", Uuid::new_v4().simple());

    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u1))
            .await?,
    )
    .await?;

    // `pr` means "present and non-empty" and takes no value argument.
    let query = format!("filter={}", filter_escape("userName pr"));
    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&query).await?).await?;
    assert!(listed.total_results >= 1);
    assert!(
        listed.resources.iter().any(|u| u.user_name == u1),
        "pr should match users with a present userName"
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_filter_and_chain() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let u1 = format!("scim-alpha-{}", Uuid::new_v4().simple());
    let u2 = format!("scim-alpha-beta-{}", Uuid::new_v4().simple());
    let u3 = format!("scim-omega-{}", Uuid::new_v4().simple());

    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u1))
            .await?,
    )
    .await?;
    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u2))
            .await?,
    )
    .await?;
    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u3))
            .await?,
    )
    .await?;

    // sw "scim-alpha" AND sw "scim-alpha-beta" should only match u2.
    let query = format!(
        "filter={}",
        filter_escape(r#"userName sw "scim-alpha-beta" and userName sw "scim-alpha""#)
    );
    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&query).await?).await?;
    assert_eq!(listed.total_results, 1);
    assert_eq!(listed.resources[0].user_name, u2);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_filter_or_chain() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let u1 = format!("scim-alpha-{}", Uuid::new_v4().simple());
    let u2 = format!("scim-omega-{}", Uuid::new_v4().simple());

    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u1))
            .await?,
    )
    .await?;
    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&u2))
            .await?,
    )
    .await?;

    // eq u1 OR eq u2 should return both.
    let query = format!(
        "filter={}",
        filter_escape(&format!(r#"userName eq "{u1}" or userName eq "{u2}""#))
    );
    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&query).await?).await?;
    assert_eq!(listed.total_results, 2);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_filter_rejects_unsupported_operator() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    // `gt` is not in our allowed operator set (only eq, ne, co, sw, pr).
    let query = format!("filter={}", filter_escape(r#"userName gt "scim""#));
    let rsp = provisioned.client.list_users(&query).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidFilter"));

    provisioned.cleanup().await?;
    Ok(())
}

fn filter_escape(raw: &str) -> String {
    raw.replace(' ', "%20")
        .replace('"', "%22")
        .replace('&', "%26")
        .replace('(', "%28")
        .replace(')', "%29")
}
