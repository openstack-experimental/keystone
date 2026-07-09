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
//! Live-HTTP request-side `schemas` validation (RFC 7644 §3.3): `POST`/`PUT`
//! bodies must declare the resource's core schema URI, or `400
//! invalidValue`.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{GROUP_SCHEMA, ScimGroupWrite, ScimUserWrite, USER_SCHEMA, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_user_create_rejects_missing_schemas() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let mut req = ScimUserWrite::new(format!("scim-user-{}", Uuid::new_v4().simple()));
    req.schemas = vec![];
    let rsp = provisioned.client.create_user(&req).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidValue"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_create_rejects_wrong_schema_uri() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let mut req = ScimUserWrite::new(format!("scim-user-{}", Uuid::new_v4().simple()));
    req.schemas = vec![GROUP_SCHEMA.to_string()];
    let rsp = provisioned.client.create_user(&req).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidValue"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_create_accepts_correct_schema_uri() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let req = ScimUserWrite::new(format!("scim-user-{}", Uuid::new_v4().simple()));
    assert_eq!(req.schemas, vec![USER_SCHEMA.to_string()]);
    let created: test_api::scim::ScimUser =
        expect_ok(provisioned.client.create_user(&req).await?).await?;
    assert!(created.schemas.iter().any(|s| s == USER_SCHEMA));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_update_rejects_missing_schemas() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let created: test_api::scim::ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!(
                "scim-user-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let mut req = ScimUserWrite::new(created.user_name.clone());
    req.schemas = vec![];
    let rsp = provisioned
        .client
        .update_user(&created.id, &req, None)
        .await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidValue"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_group_create_rejects_missing_schemas() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let mut req = ScimGroupWrite::new(format!("scim-group-{}", Uuid::new_v4().simple()));
    req.schemas = vec![];
    let rsp = provisioned.client.create_group(&req).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidValue"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_group_update_rejects_missing_schemas() -> Result<()> {
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

    let mut req = ScimGroupWrite::new(created.display_name.clone());
    req.schemas = vec![];
    let rsp = provisioned
        .client
        .update_group(&created.id, &req, None)
        .await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidValue"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_patch_rejects_wrong_patchop_schema() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let created: test_api::scim::ScimUser = expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!(
                "scim-user-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let mut patch = test_api::scim::ScimPatchRequest::replace("active", serde_json::json!(false));
    patch.schemas = vec![USER_SCHEMA.to_string()];
    let rsp = provisioned.client.patch_user(&created.id, &patch).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidValue"));

    provisioned.cleanup().await?;
    Ok(())
}
