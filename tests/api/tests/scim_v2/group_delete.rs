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
//! Live-HTTP `DELETE /SCIM/v2/{domain_id}/Groups/{id}` (ADR 0024 §6.B):
//! tombstone semantics, idempotent second delete, and list exclusion.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimGroup, ScimGroupWrite, ScimListResponse, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_delete_tombstones_group() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let display_name = format!("scim-group-{}", Uuid::new_v4().simple());

    let created: ScimGroup = expect_ok(
        provisioned
            .client
            .create_group(&ScimGroupWrite::new(&display_name))
            .await?,
    )
    .await?;

    let delete_rsp = provisioned.client.delete_group(&created.id).await?;
    assert_eq!(delete_rsp.status, StatusCode::NO_CONTENT);

    // After tombstone, show must 404 (ADR 0024 §3.C Ownership Fencing
    // indistinguishable-from-nonexistent).
    let show_after = provisioned.client.show_group(&created.id).await?;
    assert_eq!(
        show_after.status,
        StatusCode::NOT_FOUND,
        "a tombstoned group must 404"
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delete_idempotent_on_repeat() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let display_name = format!("scim-group-{}", Uuid::new_v4().simple());

    let created: ScimGroup = expect_ok(
        provisioned
            .client
            .create_group(&ScimGroupWrite::new(&display_name))
            .await?,
    )
    .await?;

    // First delete: 204.
    assert_eq!(
        provisioned.client.delete_group(&created.id).await?.status,
        StatusCode::NO_CONTENT
    );

    // Second delete: 404 (already deprovisioned).
    let second = provisioned.client.delete_group(&created.id).await?;
    assert_eq!(
        second.status,
        StatusCode::NOT_FOUND,
        "idempotent second delete must 404, not 204"
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_deleted_group_excluded_from_list() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let display_name = format!("scim-group-{}", Uuid::new_v4().simple());

    let created: ScimGroup = expect_ok(
        provisioned
            .client
            .create_group(&ScimGroupWrite::new(&display_name))
            .await?,
    )
    .await?;

    provisioned.client.delete_group(&created.id).await?;

    let listed: ScimListResponse<ScimGroup> =
        expect_ok(provisioned.client.list_groups("").await?).await?;
    assert!(
        !listed.resources.iter().any(|g| g.id == created.id),
        "tombstoned group must be excluded from list"
    );

    provisioned.cleanup().await?;
    Ok(())
}
