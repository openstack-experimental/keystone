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

use eyre::Result;

use openstack_keystone_api_types::v3::auth::token::*;

use test_api::auth::token::check_token;
use test_api::common::*;

#[tokio::test]
async fn test_validate_own() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;

    let _auth_rsp: TokenResponse = check_token(
        &admin_client,
        admin_client.token.as_ref().expect("must be authenticated"),
    )
    .await?
    .json()
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_validate_nocatalog_flag() -> Result<()> {
    let mut admin_client = TestClient::default()?;
    admin_client.auth_admin().await?;
    let subject = admin_client.token.as_ref().expect("must be authenticated");

    // Without nocatalog – catalog must be present.
    let rsp: TokenResponse = check_token(&admin_client, subject).await?.json().await?;
    assert!(
        rsp.token.catalog.is_some(),
        "catalog must be present when nocatalog is not set"
    );

    // With nocatalog=true – catalog must be absent.
    let rsp_no: TokenResponse = check_token_with_nocatalog(&admin_client, subject, true)
        .await?
        .json()
        .await?;
    assert!(
        rsp_no.token.catalog.is_none(),
        "catalog must be absent when nocatalog=true"
    );

    // With nocatalog=false – catalog must be present (same as default).
    let rsp_yes: TokenResponse = check_token_with_nocatalog(&admin_client, subject, false)
        .await?
        .json()
        .await?;
    assert!(
        rsp_yes.token.catalog.is_some(),
        "catalog must be present when nocatalog=false"
    );

    Ok(())
}

/// Like `check_token` but able to pass `nocatalog` query parameter.
async fn check_token_with_nocatalog(
    tc: &TestClient,
    subject_token: &secrecy::SecretString,
    nocatalog: bool,
) -> Result<reqwest::Response> {
    use secrecy::ExposeSecret;

    let mut hdr = reqwest::header::HeaderValue::from_str(subject_token.expose_secret())?;
    hdr.set_sensitive(true);
    let mut url = tc.base_url.join("v3/auth/tokens")?;
    url.query_pairs_mut()
        .append_pair("nocatalog", &nocatalog.to_string());
    Ok(tc
        .client
        .get(url)
        .header("x-subject-token", hdr)
        .send()
        .await?)
}
