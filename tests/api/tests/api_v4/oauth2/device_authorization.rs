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
//! Live-server `POST /v4/oauth2/{domain_id}/device_authorization` (RFC 8628
//! §3.1/§3.2, ADR 0026 §7.C). Complements `tests/integration/src/
//! oauth2_device_grant.rs`'s provider-level coverage with the real HTTP
//! wire shape and status codes.

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v4::oauth2_client::GrantType;

use test_api::oauth2::*;

#[tokio::test]
#[traced_test]
async fn test_device_authorization_returns_rfc8628_shape() -> Result<()> {
    let provider_id = format!("device-grant-api-test-{}", Uuid::new_v4().simple());
    let (client_id, _secret) = register_client(
        "default",
        &provider_id,
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;

    let start = start_device_authorization("default", &client_id, Some("openid")).await?;

    assert!(!start.device_code.is_empty());
    // "XXXX-XXXX" shape (ADR 0026 §7.C).
    assert_eq!(start.user_code.len(), 9);
    assert_eq!(start.user_code.chars().nth(4), Some('-'));
    assert!(start.verification_uri_complete.contains(&start.user_code));
    assert!(start.expires_in > 0);
    assert!(start.interval > 0);

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_device_authorization_rejects_unknown_client() -> Result<()> {
    let err = start_device_authorization("default", "no-such-client", None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("400") || err.to_string().contains("failed"));
    Ok(())
}
