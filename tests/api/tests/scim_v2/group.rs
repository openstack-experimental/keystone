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
//! Live-HTTP, live-OPA `/SCIM/v2/{domain_id}/Groups` (ADR 0024 §3, §4, §6.B,
//! §7), the counterpart of `crates/keystone/src/scim/group/*.rs`'s
//! mocked-state handler tests.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{
    ScimGroup, ScimGroupMember, ScimGroupWrite, ScimListResponse, ScimUserWrite, expect_ok,
};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_create_show_list_roundtrip() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let display_name = format!("scim-group-{}", Uuid::new_v4().simple());

    let create_rsp = provisioned
        .client
        .create_group(&ScimGroupWrite::new(&display_name))
        .await?;
    assert_eq!(create_rsp.status, StatusCode::CREATED);
    let created: ScimGroup = create_rsp.json()?;
    assert_eq!(created.display_name, display_name);
    assert!(created.members.is_empty());

    let shown: ScimGroup = expect_ok(provisioned.client.show_group(&created.id).await?).await?;
    assert_eq!(shown.id, created.id);

    let listed: ScimListResponse<ScimGroup> =
        expect_ok(provisioned.client.list_groups("").await?).await?;
    assert!(listed.resources.iter().any(|g| g.id == created.id));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_rejects_duplicate_display_name() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let display_name = format!("scim-group-{}", Uuid::new_v4().simple());

    let first = provisioned
        .client
        .create_group(&ScimGroupWrite::new(&display_name))
        .await?;
    assert_eq!(first.status, StatusCode::CREATED);

    let second = provisioned
        .client
        .create_group(&ScimGroupWrite::new(&display_name))
        .await?;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert_eq!(second.error()?.scim_type.as_deref(), Some("uniqueness"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_replaces_membership() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let member: test_api::scim::ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!(
                "scim-user-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let display_name = format!("scim-group-{}", Uuid::new_v4().simple());
    let created: ScimGroup = expect_ok(
        provisioned
            .client
            .create_group(&ScimGroupWrite::new(&display_name))
            .await?,
    )
    .await?;
    assert!(created.members.is_empty());

    let mut write = ScimGroupWrite::new(&display_name);
    write.members = vec![ScimGroupMember {
        value: member.id.clone(),
    }];
    let updated: ScimGroup = expect_ok(
        provisioned
            .client
            .update_group(&created.id, &write, None)
            .await?,
    )
    .await?;
    assert_eq!(updated.members.len(), 1);
    assert_eq!(updated.members[0].value, member.id);

    provisioned.cleanup().await?;
    Ok(())
}
