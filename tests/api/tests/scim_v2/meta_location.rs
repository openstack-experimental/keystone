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
//! Live-HTTP `meta.location` / `Location` header (RFC 7644 §3.1): every
//! `User`/`Group` response body carries `meta.location`, and `201 Created`
//! responses also carry the HTTP `Location` header (not mandated elsewhere
//! by the RFC).

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimGroupWrite, ScimUser, ScimUserWrite, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_user_create_response_includes_location_header() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let username = format!("scim-user-{}", Uuid::new_v4().simple());
    let rsp = provisioned
        .client
        .create_user(&ScimUserWrite::new(&username))
        .await?;
    let location = rsp.location().expect("Location header present").to_string();

    let created: ScimUser = expect_ok(rsp).await?;
    assert_eq!(
        location, created.meta.location,
        "Location header should match the body's meta.location"
    );
    assert!(
        location.ends_with(&format!("/Users/{}", created.id)),
        "location `{location}` should end with /Users/{{id}}"
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_show_includes_meta_location() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let created: ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!(
                "scim-user-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let fetched: ScimUser = expect_ok(provisioned.client.show_user(&created.id).await?).await?;
    assert!(
        fetched
            .meta
            .location
            .ends_with(&format!("/Users/{}", created.id))
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_list_items_include_meta_location() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let created: ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!(
                "scim-user-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let listed: test_api::scim::ScimListResponse<ScimUser> = expect_ok(
        provisioned
            .client
            .list_users(&format!("filter=id eq \"{}\"", created.id))
            .await?,
    )
    .await?;
    assert_eq!(listed.resources.len(), 1);
    assert!(
        listed.resources[0]
            .meta
            .location
            .ends_with(&format!("/Users/{}", created.id))
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_group_create_response_includes_location_header() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let display_name = format!("scim-group-{}", Uuid::new_v4().simple());
    let rsp = provisioned
        .client
        .create_group(&ScimGroupWrite::new(&display_name))
        .await?;
    let location = rsp.location().expect("Location header present").to_string();

    let created: test_api::scim::ScimGroup = expect_ok(rsp).await?;
    assert_eq!(location, created.meta.location);
    assert!(location.ends_with(&format!("/Groups/{}", created.id)));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_group_show_includes_meta_location() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let created: test_api::scim::ScimGroup = expect_ok(
        provisioned
            .client
            .create_group(&ScimGroupWrite::new(format!(
                "scim-group-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let fetched: test_api::scim::ScimGroup =
        expect_ok(provisioned.client.show_group(&created.id).await?).await?;
    assert!(
        fetched
            .meta
            .location
            .ends_with(&format!("/Groups/{}", created.id))
    );

    provisioned.cleanup().await?;
    Ok(())
}
