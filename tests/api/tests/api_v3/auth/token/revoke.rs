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

use eyre::{OptionExt, Result};
use reqwest::StatusCode;
use secrecy::SecretString;
use tracing_test::traced_test;

use test_api::asserts::assert_unauthorized;
use test_api::auth::token::{authenticate_by_token, check_token, revoke_token};
use test_api::common::TestClient;

#[tokio::test]
async fn test_invalid_token_cannot_be_used_for_authentication() -> Result<()> {
    let client = TestClient::default()?;
    let invalid = SecretString::from("invalid-token");
    let response = authenticate_by_token(&client, &invalid, None).await?;

    assert_unauthorized(
        response.error_for_status(),
        "an invalid token must not authenticate for a new token",
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_revoked_token_cannot_be_validated_or_used_for_authentication() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;

    let mut subject_client = TestClient::default()?;
    subject_client.auth_admin().await?;
    let subject_token = subject_client
        .token
        .as_ref()
        .ok_or_eyre("the subject client must be authenticated")?;

    assert_eq!(
        check_token(&admin_client, subject_token).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        revoke_token(&admin_client, subject_token).await?.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        check_token(&admin_client, subject_token).await?.status(),
        StatusCode::NOT_FOUND
    );

    let response = authenticate_by_token(&admin_client, subject_token, None).await?;
    assert_unauthorized(
        response.error_for_status(),
        "a revoked token must not authenticate for a new token",
    );
    Ok(())
}
