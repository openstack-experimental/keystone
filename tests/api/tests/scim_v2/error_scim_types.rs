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
//! Live-HTTP `scimType` coverage (RFC 7644 §3.12 Table 9): `mutability` for
//! `PATCH` targeting a real-but-immutable attribute (`id`/`meta`), and
//! `invalidSyntax` for a malformed JSON body -- both distinct from the
//! pre-existing `invalidPath` (not a real/supported attribute at all).
//! `noTarget` and `tooMany` are intentionally not implemented (see ADR 0024
//! and the compliance-hardening plan): `noTarget` because
//! remove-of-an-absent-attribute stays an idempotent no-op (matches
//! real-world SCIM client sync/retry expectations), `tooMany` because
//! truncation + pagination `Link` headers is the RFC-sanctioned
//! alternative.

use eyre::Result;
use reqwest::{Method, StatusCode};
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimPatchRequest, ScimUser, ScimUserWrite, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_patch_immutable_id_returns_mutability_scim_type() -> Result<()> {
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

    let patch = ScimPatchRequest::replace("id", serde_json::json!("some-other-id"));
    let rsp = provisioned.client.patch_user(&created.id, &patch).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("mutability"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_patch_unrecognized_path_returns_invalid_path_scim_type() -> Result<()> {
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

    // `nickName` isn't a real/supported attribute at all -- distinct from
    // `id`, which is real but immutable.
    let patch = ScimPatchRequest::replace("nickName", serde_json::json!("nick"));
    let rsp = provisioned.client.patch_user(&created.id, &patch).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidPath"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_malformed_json_body_returns_scim_error_envelope() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned
        .client
        .raw_with_body(
            Method::POST,
            "Users",
            Some("application/json"),
            r#"{"userName": "broken", "schemas": [}"#,
        )
        .await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    let body = rsp.error()?;
    assert_eq!(body.scim_type.as_deref(), Some("invalidSyntax"));
    assert!(
        !body.schemas.is_empty(),
        "error body must carry a schemas array"
    );

    provisioned.cleanup().await?;
    Ok(())
}
