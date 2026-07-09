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
//! Live-HTTP discovery endpoints: `GET /ServiceProviderConfig`, `GET /Schemas`,
//! `GET /ResourceTypes` (ADR 0024 §5.A). These endpoints are supposed to be
//! discoverable without authentication, but `ScimTestClient` uses bearer auth,
//! which is still valid for testing (the endpoints accept auth, they just
//! don't require it). Wire-format validation against the exact JSON shapes an
//! enterprise IdP would parse.

use eyre::Result;
use reqwest::StatusCode;
use serde_json::Value;
use tracing_test::traced_test;

use test_api::scim::expect_ok;

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_service_provider_config_honestly_advertises_limitations() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned.client.service_provider_config().await?;
    assert_eq!(rsp.status, StatusCode::OK);
    let body: Value = expect_ok(rsp).await?;

    // Verify the discovery document honestly advertises what's not supported.
    assert_eq!(body["bulk"]["supported"], false);
    assert_eq!(body["sort"]["supported"], false);
    assert_eq!(body["changePassword"]["supported"], false);

    // Verify supported features are advertised.
    assert_eq!(body["patch"]["supported"], true);
    assert_eq!(body["filter"]["supported"], true);
    assert_eq!(body["filter"]["maxResults"], 200);
    assert_eq!(body["etag"]["supported"], true);

    // Verify the authentication scheme is what we expect (ADR 0021).
    assert_eq!(body["authenticationSchemes"].as_array().unwrap().len(), 1);
    assert_eq!(body["authenticationSchemes"][0]["type"], "oauthbearertoken");

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_schemas_lists_user_and_group() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned.client.schemas().await?;
    assert_eq!(rsp.status, StatusCode::OK);
    let body: Value = expect_ok(rsp).await?;

    assert_eq!(body["totalResults"], 2);
    let resources = body["Resources"].as_array().unwrap();
    assert_eq!(resources.len(), 2);

    let schema_ids: Vec<&str> = resources
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert!(schema_ids.contains(&"urn:ietf:params:scim:schemas:core:2.0:User"));
    assert!(schema_ids.contains(&"urn:ietf:params:scim:schemas:core:2.0:Group"));

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_resource_types_lists_endpoints() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let rsp = provisioned.client.resource_types().await?;
    assert_eq!(rsp.status, StatusCode::OK);
    let body: Value = expect_ok(rsp).await?;

    assert_eq!(body["totalResults"], 2);

    let endpoints: Vec<&str> = body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["endpoint"].as_str().unwrap())
        .collect();
    assert_eq!(endpoints, vec!["/Users", "/Groups"]);

    provisioned.cleanup().await?;
    Ok(())
}
