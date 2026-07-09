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
//! Live-HTTP `/Bulk` (RFC 7644 §3.7) and `/Me` (RFC 7644 §3.11): both are
//! explicitly out of scope for ADR 0024, but a client probing them should
//! get a clean `501` with a `ScimErrorBody`, not Axum's default
//! non-SCIM-shaped `404`.

use eyre::Result;
use reqwest::{Method, StatusCode};
use tracing_test::traced_test;

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_bulk_returns_501_with_scim_error_body() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned
        .client
        .raw_with_body(Method::POST, "Bulk", Some("application/json"), "{}")
        .await?;
    assert_eq!(rsp.status, StatusCode::NOT_IMPLEMENTED);
    let body = rsp.error()?;
    assert!(!body.detail.is_empty());

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_me_returns_scim_shaped_response_not_default_404() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned.client.raw(Method::GET, "Me").await?;
    assert_eq!(rsp.status, StatusCode::NOT_IMPLEMENTED);
    let body = rsp.error()?;
    assert!(!body.detail.is_empty());

    provisioned.cleanup().await?;
    Ok(())
}
