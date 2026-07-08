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
//! Live-HTTP `PATCH` (ADR 0024 §5.C), the counterpart of
//! `crates/keystone/src/scim/patch.rs`'s mocked-state handler tests: the
//! `path` allowlist and RFC 7644 `Operations` shape, driven end to end.

use eyre::Result;
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimPatchRequest, ScimUser, ScimUserWrite, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_patch_replace_display_name() -> Result<()> {
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

    let patch = ScimPatchRequest::replace("displayName", json!("Patched Display Name"));
    let patched: ScimUser =
        expect_ok(provisioned.client.patch_user(&created.id, &patch).await?).await?;
    assert_eq!(
        patched.display_name.as_deref(),
        Some("Patched Display Name")
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_patch_replace_active() -> Result<()> {
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
    assert!(created.active);

    let patch = ScimPatchRequest::replace("active", json!(false));
    let patched: ScimUser =
        expect_ok(provisioned.client.patch_user(&created.id, &patch).await?).await?;
    assert!(!patched.active);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_patch_rejects_path_outside_allowlist() -> Result<()> {
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

    // `id` is server-assigned and immutable; not on the ADR 0024 §5.C
    // allowlist for User.
    let patch = ScimPatchRequest::replace("id", json!("attacker-controlled"));
    let rsp = provisioned.client.patch_user(&created.id, &patch).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    assert_eq!(rsp.error()?.scim_type.as_deref(), Some("invalidPath"));

    provisioned.cleanup().await?;
    Ok(())
}
