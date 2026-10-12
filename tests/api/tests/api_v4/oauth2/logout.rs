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
//! Live-server client registration of the logout endpoints (OIDC Back-Channel
//! and Front-Channel Logout 1.0): the fields round-trip and are validated.

use eyre::Result;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::common::TestClient;
use test_api::oauth2::create_test_domain;

async fn create_client(domain_id: &str, extra: Value) -> Result<(StatusCode, Value)> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let mut payload = json!({
        "provider_id": format!("logout-{}", Uuid::new_v4().simple()),
        "name": "logout test client",
        "confidential": false,
        "grant_types": ["authorization_code"],
        "allowed_scopes": ["openid"],
        "token_endpoint_auth_method": "none",
        "require_pkce": true,
    });
    if let (Some(p), Some(e)) = (payload.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    let rsp = admin
        .client
        .post(
            admin
                .base_url
                .join(&format!("v4/oauth2/{domain_id}/clients"))?,
        )
        .json(&json!({ "oauth2_client": payload }))
        .send()
        .await?;
    let status = rsp.status();
    let body = rsp.json().await.unwrap_or(Value::Null);
    Ok((status, body))
}

#[tokio::test]
#[traced_test]
async fn test_client_logout_endpoints_round_trip() -> Result<()> {
    let domain_id = create_test_domain(&format!("logout-test-{}", Uuid::new_v4().simple())).await?;
    let (status, body) = create_client(
        &domain_id,
        json!({
            "backchannel_logout_uri": "https://rp.example.com/backchannel",
            "backchannel_logout_session_required": true,
            "frontchannel_logout_uri": "https://rp.example.com/frontchannel",
            "frontchannel_logout_session_required": true,
        }),
    )
    .await?;
    assert!(status.is_success(), "{status}: {body}");
    let client = &body["oauth2_client"];
    assert_eq!(
        client["backchannel_logout_uri"],
        "https://rp.example.com/backchannel"
    );
    assert_eq!(client["backchannel_logout_session_required"], true);
    assert_eq!(
        client["frontchannel_logout_uri"],
        "https://rp.example.com/frontchannel"
    );
    assert_eq!(client["frontchannel_logout_session_required"], true);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_session_required_needs_a_logout_uri() -> Result<()> {
    let domain_id = create_test_domain(&format!("logout-test-{}", Uuid::new_v4().simple())).await?;
    for extra in [
        json!({"backchannel_logout_session_required": true}),
        json!({"frontchannel_logout_session_required": true}),
        json!({"frontchannel_logout_uri": "http://rp.example.com/frontchannel"}),
    ] {
        let (status, body) = create_client(&domain_id, extra.clone()).await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{extra}: {body}");
    }
    Ok(())
}
