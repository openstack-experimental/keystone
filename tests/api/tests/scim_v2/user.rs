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
//! Live-HTTP, live-OPA `/SCIM/v2/{domain_id}/Users` (ADR 0024 §3, §4, §6.A,
//! §8), the counterpart of `crates/keystone/src/scim/user/*.rs`'s
//! mocked-state handler tests.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimListResponse, ScimUser, ScimUserWrite, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_create_show_list_roundtrip() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let username = format!("scim-user-{}", Uuid::new_v4().simple());

    let create_rsp = provisioned
        .client
        .create_user(&ScimUserWrite::new(&username))
        .await?;
    assert_eq!(create_rsp.status, StatusCode::CREATED);
    let created: ScimUser = create_rsp.json()?;
    assert_eq!(created.user_name, username);
    assert!(created.active);

    let shown: ScimUser = expect_ok(provisioned.client.show_user(&created.id).await?).await?;
    assert_eq!(shown.id, created.id);
    assert_eq!(shown.user_name, username);

    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users("").await?).await?;
    assert!(listed.resources.iter().any(|u| u.id == created.id));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_rejects_duplicate_username() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let username = format!("scim-user-{}", Uuid::new_v4().simple());

    let first = provisioned
        .client
        .create_user(&ScimUserWrite::new(&username))
        .await?;
    assert_eq!(first.status, StatusCode::CREATED);

    let second = provisioned
        .client
        .create_user(&ScimUserWrite::new(&username))
        .await?;
    assert_eq!(second.status, StatusCode::CONFLICT);
    let body = second.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("uniqueness"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delete_tombstones_user() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let username = format!("scim-user-{}", Uuid::new_v4().simple());

    let created: ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&username))
            .await?,
    )
    .await?;

    let delete_rsp = provisioned.client.delete_user(&created.id).await?;
    assert_eq!(delete_rsp.status, StatusCode::NO_CONTENT);

    let show_after_delete = provisioned.client.show_user(&created.id).await?;
    assert_eq!(
        show_after_delete.status,
        StatusCode::NOT_FOUND,
        "a tombstoned resource must 404, not show as deleted (ADR 0024 §3.C \
         Ownership Fencing indistinguishable-from-nonexistent)"
    );

    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users("").await?).await?;
    assert!(!listed.resources.iter().any(|u| u.id == created.id));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_denied_without_scim_provisioner_role() -> Result<()> {
    // A realm whose mapping ruleset grants no roles at all: the Realm
    // Activation Gate (§2.B) admits the request, but
    // `identity/scim/user/create` must still deny it -- these are two
    // independent checks (extractor vs. handler-level OPA enforcement).
    let provisioned = super::common::provision_scim_realm_without_role().await?;

    let username = format!("scim-user-{}", Uuid::new_v4().simple());
    let rsp = provisioned
        .client
        .create_user(&ScimUserWrite::new(&username))
        .await?;
    assert_eq!(rsp.status, StatusCode::FORBIDDEN);

    provisioned.cleanup().await?;
    Ok(())
}
