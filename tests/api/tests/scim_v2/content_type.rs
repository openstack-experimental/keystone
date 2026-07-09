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
//! Live-HTTP content-type negotiation (RFC 7644 §3.1): `POST`/`PUT`/`PATCH`
//! bodies must declare `application/scim+json` or, for backwards-compatible
//! clients, plain `application/json`; anything else is `415`. Every
//! response leaving the SCIM sub-router carries `Content-Type:
//! application/scim+json`.

use eyre::Result;
use reqwest::{Method, StatusCode};
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::ScimUserWrite;

use super::common::provision_scim_realm;

fn content_type_of(rsp: &test_api::scim::ScimResponse) -> Option<&str> {
    rsp.headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
}

#[tokio::test]
#[traced_test]
async fn test_post_rejects_unsupported_content_type() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let body = serde_json::to_string(&ScimUserWrite::new(format!(
        "scim-user-{}",
        Uuid::new_v4().simple()
    )))?;
    let rsp = provisioned
        .client
        .raw_with_body(Method::POST, "Users", Some("text/plain"), &body)
        .await?;
    assert_eq!(rsp.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_post_rejects_missing_content_type_with_body() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let body = serde_json::to_string(&ScimUserWrite::new(format!(
        "scim-user-{}",
        Uuid::new_v4().simple()
    )))?;
    let rsp = provisioned
        .client
        .raw_with_body(Method::POST, "Users", None, &body)
        .await?;
    assert_eq!(rsp.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_post_accepts_application_json() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let username = format!("scim-user-{}", Uuid::new_v4().simple());
    let body = serde_json::to_string(&ScimUserWrite::new(&username))?;
    let rsp = provisioned
        .client
        .raw_with_body(Method::POST, "Users", Some("application/json"), &body)
        .await?;
    assert_eq!(rsp.status, StatusCode::CREATED);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_post_accepts_application_scim_json() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let username = format!("scim-user-{}", Uuid::new_v4().simple());
    let body = serde_json::to_string(&ScimUserWrite::new(&username))?;
    let rsp = provisioned
        .client
        .raw_with_body(Method::POST, "Users", Some("application/scim+json"), &body)
        .await?;
    assert_eq!(rsp.status, StatusCode::CREATED);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_get_response_content_type_is_scim_json() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let created: test_api::scim::ScimUser = test_api::scim::expect_ok(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(format!(
                "scim-user-{}",
                Uuid::new_v4().simple()
            )))
            .await?,
    )
    .await?;

    let rsp = provisioned.client.show_user(&created.id).await?;
    assert_eq!(rsp.status, StatusCode::OK);
    assert_eq!(
        content_type_of(&rsp),
        Some("application/scim+json"),
        "GET response Content-Type should be normalized to application/scim+json"
    );

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_error_response_content_type_is_scim_json() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    // 404 on a resource that doesn't exist -- still a normal ScimApiError
    // response through the same middleware.
    let rsp = provisioned.client.show_user("nonexistent-id").await?;
    assert_eq!(rsp.status, StatusCode::NOT_FOUND);
    assert_eq!(content_type_of(&rsp), Some("application/scim+json"));

    provisioned.cleanup().await?;
    Ok(())
}
