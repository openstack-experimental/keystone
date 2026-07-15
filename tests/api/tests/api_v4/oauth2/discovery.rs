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
//! Live-server `GET /v4/oauth2/{domain_id}/.well-known/openid-configuration`
//! (RFC 8414 / OIDC Discovery 1.0, ADR 0026 §10). `well_known.rs` has
//! mocked-state unit coverage already; this exercises the document actually
//! provisioned by `tools/start-api.sh`'s real signing keys.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::oauth2::*;

#[tokio::test]
#[traced_test]
async fn test_discovery_document_lists_adr0026_endpoints_and_grants() -> Result<()> {
    // `default` is DB-seeded at bootstrap, not created through `POST
    // /v3/domains`, so it never fires `Oauth2KeyHook` and never gets OAuth2
    // signing keys -- use a domain actually created through the API so
    // `jwks`/`well-known` have something to serve.
    let domain_name = format!("discovery-test-{}", Uuid::new_v4().simple());
    let domain_id = create_test_domain(&domain_name).await?;

    // Key provisioning happens off an async event dispatch (same race
    // `tools/start-api.sh` polls around for `default`), so poll here too.
    let mut doc = serde_json::Value::Null;
    let mut status = StatusCode::NOT_FOUND;
    for _ in 0..30 {
        (status, doc) = get_well_known(&domain_id).await?;
        if status == StatusCode::OK {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(
        status,
        StatusCode::OK,
        "domain never got signing keys provisioned"
    );

    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
        "grant_types_supported",
        "scopes_supported",
    ] {
        assert!(
            !doc[field].is_null(),
            "missing required field {field}: {doc}"
        );
    }

    let token_endpoint = doc["token_endpoint"].as_str().unwrap();
    assert!(token_endpoint.ends_with(&format!("/v4/oauth2/{domain_id}/token")));
    let jwks_uri = doc["jwks_uri"].as_str().unwrap();
    assert!(jwks_uri.ends_with(&format!("/v4/oauth2/{domain_id}/jwks")));

    let grant_types: Vec<&str> = doc["grant_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(grant_types.contains(&"client_credentials"));
    assert!(grant_types.contains(&"authorization_code"));
    assert!(grant_types.contains(&"refresh_token"));
    assert!(grant_types.contains(&"device_code"));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_discovery_document_not_found_for_unprovisioned_domain() -> Result<()> {
    let (status, _doc) = get_well_known("no-such-domain").await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}
