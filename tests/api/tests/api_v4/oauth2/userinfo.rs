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
//! Live-server `GET|POST /v4/oauth2/{domain_id}/userinfo` (OIDC Core §5.3).
//!
//! Obtains a real access token through the device grant with
//! `openid profile email`, then calls `/userinfo`. Uses a freshly created
//! domain: `default` never gets OAuth2 signing keys provisioned.

use std::time::Duration;

use eyre::{Result, eyre};
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v4::oauth2_client::GrantType;

use test_api::oauth2::*;

/// Returns `(domain_id, username, access_token, id_token)`.
async fn device_tokens() -> Result<(String, String, String, String)> {
    let domain_id = create_test_domain(&format!("userinfo-{}", Uuid::new_v4().simple())).await?;
    let mut provisioned = false;
    for _ in 0..40 {
        let (status, _) = get_well_known(&domain_id).await?;
        if status == StatusCode::OK {
            provisioned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if !provisioned {
        return Err(eyre!(
            "signing keys for domain {domain_id} never provisioned"
        ));
    }

    let provider_id = format!("userinfo-test-{}", Uuid::new_v4().simple());
    let (client_id, _) = register_client(
        &domain_id,
        &provider_id,
        vec![GrantType::DeviceCode],
        vec!["openid".into(), "profile".into(), "email".into()],
        false,
    )
    .await?;
    let username = format!("userinfo-user-{}", Uuid::new_v4().simple());
    let password = "S3cur3P@ssw0rd!";
    create_test_user(&domain_id, &username, password).await?;

    let start =
        start_device_authorization(&domain_id, &client_id, Some("openid profile email")).await?;
    let session = DeviceBrowserSession::new(&domain_id)?;
    let (_, login_html) = session.submit_user_code(&start.user_code).await?;
    let login_csrf =
        extract_hidden_value(&login_html, "csrf_token").ok_or_else(|| eyre!("no login csrf"))?;
    let (_, consent_html) = session
        .submit_login(&login_csrf, &username, password)
        .await?;
    let consent_csrf = extract_hidden_value(&consent_html, "csrf_token")
        .ok_or_else(|| eyre!("no consent csrf"))?;
    let (status, _) = session.submit_consent(&consent_csrf, "allow").await?;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = poll_device_token(&domain_id, &client_id, &start.device_code).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let access = body["access_token"]
        .as_str()
        .ok_or_else(|| eyre!("no access_token in {body}"))?
        .to_string();
    let id = body["id_token"]
        .as_str()
        .ok_or_else(|| eyre!("no id_token in {body}"))?
        .to_string();
    Ok((domain_id, username, access, id))
}

#[tokio::test]
#[traced_test]
async fn test_userinfo_returns_claims_for_get_and_post() -> Result<()> {
    let (domain_id, username, access, _id) = device_tokens().await?;

    for post in [false, true] {
        let (status, _, body) = call_userinfo(&domain_id, post, Some(&access)).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["sub"].as_str().is_some_and(|s| !s.is_empty()));
        assert_eq!(body["name"], username.as_str());
        assert_eq!(body["preferred_username"], username.as_str());
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_userinfo_rejects_missing_invalid_and_id_tokens() -> Result<()> {
    let (domain_id, _username, access, id_token) = device_tokens().await?;

    let (status, www, _) = call_userinfo(&domain_id, false, None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(www.as_deref(), Some("Bearer"));

    for token in ["garbage", id_token.as_str()] {
        let (status, www, _) = call_userinfo(&domain_id, false, Some(token)).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(www.as_deref(), Some("Bearer error=\"invalid_token\""));
    }

    // A tampered signature is rejected as well.
    let tampered = format!("{access}x");
    let (status, _, _) = call_userinfo(&domain_id, false, Some(&tampered)).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_discovery_advertises_userinfo_endpoint() -> Result<()> {
    let (domain_id, _username, _access, _id) = device_tokens().await?;
    let (status, doc) = get_well_known(&domain_id).await?;
    assert_eq!(status, StatusCode::OK);
    let endpoint = doc["userinfo_endpoint"]
        .as_str()
        .ok_or_else(|| eyre!("no userinfo_endpoint in {doc}"))?;
    assert!(endpoint.ends_with(&format!("/v4/oauth2/{domain_id}/userinfo")));
    assert_eq!(
        doc["userinfo_signing_alg_values_supported"],
        serde_json::json!(["none"])
    );
    Ok(())
}
