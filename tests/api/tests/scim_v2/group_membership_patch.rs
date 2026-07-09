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
//! Live-HTTP PATCH for group membership (ADR 0024 §5.C): `add`, `remove`,
//! and `replace` rejection. These are the core provisioning operations an
//! enterprise IdP performs when synchronizing group membership.

use eyre::Result;
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{
    PATCH_SCHEMA, ScimGroup, ScimGroupMember, ScimGroupWrite, ScimPatchOperation, ScimPatchRequest,
    ScimUser, ScimUserWrite, expect_ok,
};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_group_patch_add_member() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let member: ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!(
                "scim-user-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let group: ScimGroup = expect_ok(
        provisioned
            .client
            .create_group(&ScimGroupWrite::new(format!(
                "scim-group-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;
    assert!(group.members.is_empty());

    let patch = ScimPatchRequest {
        schemas: vec![PATCH_SCHEMA.to_string()],
        operations: vec![ScimPatchOperation {
            op: "add".to_string(),
            path: Some("members".to_string()),
            value: json!([{ "value": member.id }]),
        }],
    };

    let patched: ScimGroup =
        expect_ok(provisioned.client.patch_group(&group.id, &patch).await?).await?;
    assert_eq!(patched.members.len(), 1);
    assert_eq!(patched.members[0].value, member.id);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_group_patch_remove_member() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let member: ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!(
                "scim-user-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let mut group_write = ScimGroupWrite::new(format!("scim-group-{}", Uuid::new_v4().simple()));
    group_write.members = vec![ScimGroupMember {
        value: member.id.clone(),
    }];
    let group: ScimGroup = expect_ok(provisioned.client.create_group(&group_write).await?).await?;
    assert_eq!(group.members.len(), 1);

    let patch = ScimPatchRequest {
        schemas: vec![PATCH_SCHEMA.to_string()],
        operations: vec![ScimPatchOperation {
            op: "remove".to_string(),
            path: Some("members".to_string()),
            value: json!([{ "value": member.id }]),
        }],
    };

    let patched: ScimGroup =
        expect_ok(provisioned.client.patch_group(&group.id, &patch).await?).await?;
    assert!(
        patched.members.is_empty(),
        "remove should strip the member from the group"
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_group_patch_members_replace_rejected() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let group: ScimGroup = expect_ok(
        provisioned
            .client
            .create_group(&ScimGroupWrite::new(format!(
                "scim-group-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let patch = ScimPatchRequest {
        schemas: vec![PATCH_SCHEMA.to_string()],
        operations: vec![ScimPatchOperation {
            op: "replace".to_string(),
            path: Some("members".to_string()),
            value: json!([{ "value": "some-user-id" }]),
        }],
    };

    let rsp = provisioned.client.patch_group(&group.id, &patch).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(
        body.scim_type.as_deref(),
        Some("invalidPath"),
        "members on group only supports add/remove, replace is rejected"
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_group_patch_add_invalid_member_400() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let group: ScimGroup = expect_ok(
        provisioned
            .client
            .create_group(&ScimGroupWrite::new(format!(
                "scim-group-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    // Attempt to add a user that doesn't exist in this realm.
    let patch = ScimPatchRequest {
        schemas: vec![PATCH_SCHEMA.to_string()],
        operations: vec![ScimPatchOperation {
            op: "add".to_string(),
            path: Some("members".to_string()),
            value: json!([{ "value": "nonexistent-user-id" }]),
        }],
    };

    let rsp = provisioned.client.patch_group(&group.id, &patch).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        rsp.error()?.scim_type.as_deref(),
        Some("invalidValue"),
        "adding a member not owned by this realm must return invalidValue"
    );

    provisioned.cleanup().await?;
    Ok(())
}
