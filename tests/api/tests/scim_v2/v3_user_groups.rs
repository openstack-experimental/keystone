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
//! Cross-protocol proof that SCIM membership writes are visible through
//! `GET /v3/users/{id}/groups` (issue #993).

use std::sync::Arc;

use eyre::Result;
use reqwest::StatusCode;
use serde_json::json;
use uuid::Uuid;

use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::identity::user::list_user_groups;
use test_api::scim::{
    PATCH_SCHEMA, ScimGroup, ScimGroupMember, ScimGroupWrite, ScimPatchOperation, ScimPatchRequest,
    ScimUser, ScimUserWrite, expect_ok,
};

use super::common::{ProvisionedScim, provision_scim_realm};

async fn delete_and_purge_user(provisioned: &ProvisionedScim, user_id: &str) -> Result<()> {
    let delete_result = provisioned.client.delete_user(user_id).await;
    let purge_result = provisioned.purge_resource("user", user_id).await;

    let deleted = delete_result?;
    eyre::ensure!(
        deleted.status == StatusCode::NO_CONTENT,
        "SCIM user cleanup returned {} instead of 204",
        deleted.status
    );
    purge_result
}

async fn delete_and_purge_membership_resources(
    provisioned: &ProvisionedScim,
    group_id: &str,
    user_id: &str,
) -> Result<()> {
    // SCIM deprovisioning intentionally retains memberships for tombstone
    // auditability, while the immediate purge endpoint enforces the identity
    // backend's foreign keys. Remove the membership explicitly before
    // tombstoning and purging both records.
    let patch = ScimPatchRequest {
        schemas: vec![PATCH_SCHEMA.to_string()],
        operations: vec![ScimPatchOperation {
            op: "remove".to_string(),
            path: Some("members".to_string()),
            value: json!([{ "value": user_id }]),
        }],
    };
    let membership_cleanup: Result<()> = async {
        let patched: ScimGroup =
            expect_ok(provisioned.client.patch_group(group_id, &patch).await?).await?;
        eyre::ensure!(
            patched.members.is_empty(),
            "SCIM membership removal left members behind"
        );
        Ok(())
    }
    .await;

    // Execute every cleanup operation before propagating an individual error
    // so one failed deletion does not prevent the other resource from being
    // cleaned up.
    let group_delete = provisioned.client.delete_group(group_id).await;
    let user_delete = provisioned.client.delete_user(user_id).await;
    let group_purge = provisioned.purge_resource("group", group_id).await;
    let user_purge = provisioned.purge_resource("user", user_id).await;

    membership_cleanup?;
    let group_delete = group_delete?;
    let user_delete = user_delete?;
    eyre::ensure!(
        group_delete.status == StatusCode::NO_CONTENT,
        "SCIM group cleanup returned {} instead of 204",
        group_delete.status
    );
    eyre::ensure!(
        user_delete.status == StatusCode::NO_CONTENT,
        "SCIM user cleanup returned {} instead of 204",
        user_delete.status
    );
    group_purge?;
    user_purge?;
    Ok(())
}

#[tokio::test]
async fn test_scim_membership_is_visible_in_v3_user_groups() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let provisioned = provision_scim_realm().await?;
    let member_result: Result<ScimUser> = async {
        expect_ok(
            provisioned
                .client
                .create_user(&ScimUserWrite::new(format!(
                    "scim-user-{}",
                    Uuid::new_v4().simple()
                )))
                .await?,
        )
        .await
    }
    .await;
    let member = match member_result {
        Ok(member) => member,
        Err(error) => {
            provisioned.cleanup().await?;
            return Err(error);
        }
    };

    let display_name = format!("scim-group-{}", Uuid::new_v4().simple());
    let mut group_write = ScimGroupWrite::new(&display_name);
    group_write.members = vec![ScimGroupMember {
        value: member.id.clone(),
    }];
    let group_result: Result<ScimGroup> =
        async { expect_ok(provisioned.client.create_group(&group_write).await?).await }.await;
    let group = match group_result {
        Ok(group) => group,
        Err(error) => {
            let resource_cleanup = delete_and_purge_user(&provisioned, &member.id).await;
            let fixture_cleanup = provisioned.cleanup().await;
            resource_cleanup?;
            fixture_cleanup?;
            return Err(error);
        }
    };

    let list_result = list_user_groups(&admin, &member.id).await;
    let resource_cleanup =
        delete_and_purge_membership_resources(&provisioned, &group.id, &member.id).await;
    let fixture_cleanup = provisioned.cleanup().await;

    let groups = list_result?;
    resource_cleanup?;
    fixture_cleanup?;

    assert_eq!(groups.len(), 1, "the SCIM membership must be visible in v3");
    let listed = &groups[0];
    assert_eq!(listed.id, group.id);
    assert_eq!(listed.name, display_name);
    assert_eq!(listed.domain_id, "default");
    Ok(())
}
