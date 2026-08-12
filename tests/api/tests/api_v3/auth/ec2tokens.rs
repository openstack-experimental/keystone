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
//! `POST /v3/ec2tokens` authorization and signature matrix (issue #993).
//!
//! Caller gate (`policy/ec2tokens/validate.rego`, CVE-2025-65073): the
//! endpoint itself requires an **authenticated** caller holding the
//! `admin` or `service` role — the signed EC2 request only authenticates
//! the credential owner, not the caller.
//!
//! | case | test |
//! |------|------|
//! | admin caller + valid signature → token | `test_ec2_token_issue_success_admin_caller` |
//! | unauthenticated caller | `test_ec2_token_unauthenticated` |
//! | member caller (policy denial) | `test_ec2_token_forbidden_member_caller` |
//! | wrong signature | `test_ec2_token_bad_signature_rejected` |
//! | stale timestamp | `test_ec2_token_stale_timestamp_rejected` |
//! | issued token validates at /v3/auth/tokens | `test_ec2_token_validates_at_auth_tokens` |
//! | issued token is rejected as ordinary X-Auth-Token | `test_ec2_token_rejected_as_x_auth_token` |
//! | token-from-token reauth still allowed | `test_ec2_token_reauth_allowed` |
//!
//! The signature is produced by `test_api::auth::ec2`'s independent SigV2
//! implementation (validated against the published AWS golden vector), so
//! these tests exercise the server's canonicalization rather than
//! mirroring it.

use std::sync::Arc;

use eyre::{OptionExt, Result};
use reqwest::StatusCode;
use secrecy::ExposeSecret;

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, ScopeProjectBuilder};
use openstack_keystone_api_types::v3::auth::token::TokenResponse;
use openstack_keystone_api_types::v3::os_ec2_credential::Ec2Credential;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_status, assert_unauthorized};
use test_api::auth::ec2::{ec2_token_request_body, post_ec2_token, post_ec2_token_extract};
use test_api::common::{TestClient, raw_request};
use test_api::credential::ec2::{create_ec2_credential, delete_ec2_credential};
use test_api::fixtures::{FIXTURE_PASSWORD, ProjectScopedUser, warn_on_cleanup_failure};

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

/// An admin caller token for the `x-auth-token` header.
async fn admin_token() -> Result<String> {
    let mut tc = TestClient::default()?;
    tc.auth_admin().await?;
    Ok(tc
        .token
        .as_ref()
        .ok_or_eyre("admin token must be present")?
        .expose_secret()
        .to_string())
}

/// Member fixture + its EC2 credential (created by the member itself).
async fn member_with_credential(
    admin: &Arc<AsyncOpenStack>,
) -> Result<(ProjectScopedUser, Ec2Credential)> {
    let member = ProjectScopedUser::provision(admin, "default", "member").await?;
    match create_ec2_credential(&member.session, &member.user.id, &member.project.id).await {
        Ok(cred) => Ok((member, cred)),
        Err(error) => {
            warn_on_cleanup_failure("member fixture", member.cleanup().await);
            Err(error)
        }
    }
}

async fn cleanup(
    admin: &Arc<AsyncOpenStack>,
    member: ProjectScopedUser,
    cred: &Ec2Credential,
) -> Result<()> {
    let credential_cleanup_result =
        delete_ec2_credential(admin, &member.user.id, &cred.access).await;
    let member_cleanup_result = member.cleanup().await;
    credential_cleanup_result?;
    member_cleanup_result
}

#[tokio::test]
async fn test_ec2_token_issue_success_admin_caller() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred) = member_with_credential(&admin).await?;

    let body = ec2_token_request_body(&cred.access, &cred.secret, None, None)?;
    let (status, subject_token, response) =
        post_ec2_token_extract(Some(&admin_token().await?), body).await?;

    assert_eq!(status, StatusCode::OK, "response: {response}");
    assert!(
        subject_token.is_some_and(|token| !token.is_empty()),
        "X-Subject-Token must carry the issued token"
    );
    assert_eq!(
        response["token"]["project"]["id"], cred.project_id,
        "token must be scoped to the credential's project"
    );
    assert_eq!(
        response["token"]["user"]["id"], member.user.id,
        "token must belong to the credential owner"
    );

    cleanup(&admin, member, &cred).await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_token_unauthenticated() -> Result<()> {
    let body = ec2_token_request_body("AKIA-nonexistent", "irrelevant-secret", None, None)?;
    let response = post_ec2_token(None, body).await?;
    assert_unauthorized(
        response.error_for_status(),
        "unauthenticated callers must be rejected before signature handling",
    );
    Ok(())
}

#[tokio::test]
async fn test_ec2_token_forbidden_member_caller() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred) = member_with_credential(&admin).await?;

    // Even with a perfectly valid signature over their own credential, a
    // plain member caller is not `admin`/`service` and must be denied.
    let mut member_tc = TestClient::default()?;
    member_tc
        .auth_password(
            test_api::common::get_password_auth(&member.user.name, FIXTURE_PASSWORD, "default")?,
            Some(Scope::Project(
                ScopeProjectBuilder::default()
                    .id(member.project.id.clone())
                    .domain(DomainBuilder::default().id("default").build()?)
                    .build()?,
            )),
        )
        .await?;
    let member_token = member_tc
        .token
        .as_ref()
        .ok_or_eyre("member token must be present")?
        .expose_secret()
        .to_string();

    let body = ec2_token_request_body(&cred.access, &cred.secret, None, None)?;
    let response_result = post_ec2_token(Some(&member_token), body).await;
    let cleanup_result = cleanup(&admin, member, &cred).await;

    let response = response_result?;
    cleanup_result?;
    assert_forbidden(
        response
            .error_for_status()
            .map(|response| response.status()),
        "member callers must be denied by policy",
    );
    Ok(())
}

#[tokio::test]
async fn test_ec2_token_bad_signature_rejected() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred) = member_with_credential(&admin).await?;

    let body = ec2_token_request_body(&cred.access, &cred.secret, None, Some("bogus-signature"))?;
    let response_result = post_ec2_token(Some(&admin_token().await?), body).await;
    let cleanup_result = cleanup(&admin, member, &cred).await;

    let response = response_result?;
    cleanup_result?;
    assert!(
        !response.headers().contains_key("X-Subject-Token"),
        "no token may be issued"
    );
    assert_unauthorized(
        response
            .error_for_status()
            .map(|response| response.status()),
        "a wrong signature must not authenticate",
    );
    Ok(())
}

#[tokio::test]
async fn test_ec2_token_stale_timestamp_rejected() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred) = member_with_credential(&admin).await?;

    // Correctly signed, but over a timestamp far outside the auth TTL —
    // a replayed capture must be rejected.
    let body = ec2_token_request_body(
        &cred.access,
        &cred.secret,
        Some("2011-10-03T15:19:30Z".to_string()),
        None,
    )?;
    let response_result = post_ec2_token(Some(&admin_token().await?), body).await;
    let cleanup_result = cleanup(&admin, member, &cred).await;

    let response = response_result?;
    cleanup_result?;
    assert!(
        !response.headers().contains_key("X-Subject-Token"),
        "no token may be issued"
    );
    assert_unauthorized(
        response
            .error_for_status()
            .map(|response| response.status()),
        "a stale signed request must not authenticate",
    );
    Ok(())
}

/// Obtain a real EC2-issued token for the restriction tests below.
async fn issue_ec2_token(
    admin: &Arc<AsyncOpenStack>,
) -> Result<(ProjectScopedUser, Ec2Credential, String)> {
    let (member, cred) = member_with_credential(admin).await?;
    let token_result = async {
        let body = ec2_token_request_body(&cred.access, &cred.secret, None, None)?;
        let (status, subject_token, response) =
            post_ec2_token_extract(Some(&admin_token().await?), body).await?;
        eyre::ensure!(
            status == StatusCode::OK,
            "EC2 token issuance failed with {status}: {response}"
        );
        subject_token.ok_or_eyre("token must be issued")
    }
    .await;

    match token_result {
        Ok(token) => Ok((member, cred, token)),
        Err(error) => {
            warn_on_cleanup_failure("EC2 fixture", cleanup(admin, member, &cred).await);
            Err(error)
        }
    }
}

#[tokio::test]
async fn test_ec2_token_validates_at_auth_tokens() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred, token) = issue_ec2_token(&admin).await?;

    // The one place the EC2 token remains a valid *subject*: token
    // validation by an authorized caller.
    let mut tc = TestClient::default()?;
    tc.auth_admin().await?;
    let rsp = test_api::auth::token::check_token(&tc, &token.clone().into()).await?;
    test_api::asserts::assert_response_status(
        &rsp,
        StatusCode::OK,
        "an EC2-issued token must still validate at GET /v3/auth/tokens",
    );
    let response: TokenResponse = rsp.json().await?;
    assert!(
        response
            .token
            .methods
            .iter()
            .any(|method| method == "ec2credential"),
        "token validation must expose the immutable EC2 method marker"
    );

    cleanup(&admin, member, &cred).await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_token_rejected_as_x_auth_token() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred, token) = issue_ec2_token(&admin).await?;

    let response_result = raw_request(http::Method::GET, "v3/projects", Some(&token), None).await;
    let cleanup_result = cleanup(&admin, member, &cred).await;

    let response = response_result?;
    cleanup_result?;
    assert_status(
        response
            .error_for_status()
            .map(|response| response.status()),
        StatusCode::BAD_REQUEST,
        "an EC2-issued token must not authenticate ordinary API requests",
    );
    Ok(())
}

#[tokio::test]
async fn test_ec2_token_reauth_allowed() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred, token) = issue_ec2_token(&admin).await?;

    // #1071 explicitly keeps token-from-token reauth working.
    let mut tc = TestClient::default()?;
    tc.auth_token(
        &token,
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .id(member.project.id.clone())
                .domain(DomainBuilder::default().id("default").build()?)
                .build()?,
        )),
    )
    .await?;
    assert!(
        tc.token.is_some(),
        "token-from-token reauth with an EC2-issued token must succeed"
    );

    cleanup(&admin, member, &cred).await?;
    Ok(())
}
