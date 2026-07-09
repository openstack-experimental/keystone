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
//! Live-HTTP method-routing sanity checks (RFC 7644 §3.2): an unmapped HTTP
//! method on a *mapped* path should return `405 Method Not Allowed`, not a
//! generic `404`. Axum's default behavior through `.nest()` composition
//! isn't guaranteed to survive unchanged across versions, so this is
//! verified directly rather than assumed -- other compliance-suite phases
//! don't depend on this file, it's a standalone sanity check.

use eyre::Result;
use reqwest::{Method, StatusCode};
use tracing_test::traced_test;

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_users_collection_rejects_delete_with_405() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned.client.raw(Method::DELETE, "Users").await?;
    assert_eq!(rsp.status, StatusCode::METHOD_NOT_ALLOWED);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_resource_rejects_post_with_405() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    // `/Users/{id}` only maps GET/PUT/PATCH/DELETE -- POST is unmapped.
    let rsp = provisioned
        .client
        .raw(Method::POST, "Users/nonexistent-id")
        .await?;
    assert_eq!(rsp.status, StatusCode::METHOD_NOT_ALLOWED);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_groups_collection_rejects_put_with_405() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned.client.raw(Method::PUT, "Groups").await?;
    assert_eq!(rsp.status, StatusCode::METHOD_NOT_ALLOWED);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_group_resource_rejects_post_with_405() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned
        .client
        .raw(Method::POST, "Groups/nonexistent-id")
        .await?;
    assert_eq!(rsp.status, StatusCode::METHOD_NOT_ALLOWED);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_discovery_endpoint_rejects_post_with_405() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    // Discovery endpoints only map GET.
    let rsp = provisioned
        .client
        .raw(Method::POST, "ServiceProviderConfig")
        .await?;
    assert_eq!(rsp.status, StatusCode::METHOD_NOT_ALLOWED);

    provisioned.cleanup().await?;
    Ok(())
}
