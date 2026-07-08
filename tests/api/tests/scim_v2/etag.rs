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
//! Live-HTTP `ETag`/`If-Match` CAS (ADR 0024 §5.E), the counterpart of
//! `crates/keystone/src/scim/etag.rs`'s parsing unit tests: driven through
//! the real `show`/`update` handlers, confirming the header round-trips and
//! the precondition is actually enforced against the live backend.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimUser, ScimUserWrite, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_show_returns_etag() -> Result<()> {
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

    let shown = provisioned.client.show_user(&created.id).await?;
    assert_eq!(shown.status, StatusCode::OK);
    assert!(shown.etag().is_some(), "show response must carry an ETag");

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_with_correct_if_match_succeeds() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let username = format!("scim-user-{}", Uuid::new_v4().simple());
    let create_rsp = provisioned
        .client
        .create_user(&ScimUserWrite::new(&username))
        .await?;
    let etag = create_rsp
        .etag()
        .expect("create response must carry an ETag")
        .to_string();
    let created: ScimUser = create_rsp.json()?;

    let mut write = ScimUserWrite::new(&username);
    write.display_name = Some("updated via correct If-Match".to_string());
    let update_rsp = provisioned
        .client
        .update_user(&created.id, &write, Some(&etag))
        .await?;
    assert_eq!(update_rsp.status, StatusCode::OK);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_with_stale_if_match_is_rejected() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let username = format!("scim-user-{}", Uuid::new_v4().simple());
    let created: ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&username))
            .await?,
    )
    .await?;

    // Advance the resource's version once so the original ETag is stale.
    let mut write = ScimUserWrite::new(&username);
    write.display_name = Some("first update".to_string());
    let first_update = provisioned
        .client
        .update_user(&created.id, &write, None)
        .await?;
    assert_eq!(first_update.status, StatusCode::OK);

    let stale_etag = r#"W/"0""#;
    let mut second_write = ScimUserWrite::new(&username);
    second_write.display_name = Some("second update, should be rejected".to_string());
    let rsp = provisioned
        .client
        .update_user(&created.id, &second_write, Some(stale_etag))
        .await?;
    assert_eq!(rsp.status, StatusCode::PRECONDITION_FAILED);

    provisioned.cleanup().await?;
    Ok(())
}
