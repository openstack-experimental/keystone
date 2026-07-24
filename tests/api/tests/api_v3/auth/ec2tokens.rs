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
//! | admin caller + valid signature → token | `issue_success_admin_caller` |
//! | unauthenticated caller | `unauthenticated` |
//! | member caller (policy denial) | `forbidden_member_caller` |
//! | wrong signature | `bad_signature_rejected` |
//! | stale timestamp | `stale_timestamp_rejected` |
//! | issued token unusable elsewhere (#1071) | `token_rejected_on_regular_endpoint` |
//! | issued token validates at /v3/auth/tokens | `token_validates_at_auth_tokens` |
//! | token-from-token reauth still allowed | `token_reauth_allowed` |
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

use test_api::auth::ec2::{ec2_token_request_body, post_ec2_token_extract};
use test_api::common::{TestClient, raw_request};
use test_api::credential::ec2::{create_ec2_credential, delete_ec2_credential, get_ec2_credential};
use test_api::fixtures::{FIXTURE_PASSWORD, ProjectScopedUser};

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
    let cred = create_ec2_credential(&member.session, &member.user.id, &member.project.id).await?;
    Ok((member, cred))
}

async fn cleanup(
    admin: &Arc<AsyncOpenStack>,
    member: ProjectScopedUser,
    cred: &Ec2Credential,
) -> Result<()> {
    delete_ec2_credential(admin, &member.user.id, &cred.access).await?;
    member.cleanup().await?;
    Ok(())
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
    let (status, _, _) = post_ec2_token_extract(None, body).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated callers must be rejected before signature handling"
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
    let (status, _, response) = post_ec2_token_extract(Some(&member_token), body).await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "member callers must be denied by policy; response: {response}"
    );

    cleanup(&admin, member, &cred).await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_token_bad_signature_rejected() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred) = member_with_credential(&admin).await?;

    let body = ec2_token_request_body(&cred.access, &cred.secret, None, Some("bogus-signature"))?;
    let (status, subject_token, _) =
        post_ec2_token_extract(Some(&admin_token().await?), body).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a wrong signature must not authenticate"
    );
    assert!(subject_token.is_none(), "no token may be issued");

    cleanup(&admin, member, &cred).await?;
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
    let (status, subject_token, _) =
        post_ec2_token_extract(Some(&admin_token().await?), body).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a stale signed request must not authenticate"
    );
    assert!(subject_token.is_none(), "no token may be issued");

    cleanup(&admin, member, &cred).await?;
    Ok(())
}

/// Obtain a real EC2-issued token for the restriction tests below.
async fn issue_ec2_token(
    admin: &Arc<AsyncOpenStack>,
) -> Result<(ProjectScopedUser, Ec2Credential, String)> {
    let (member, cred) = member_with_credential(admin).await?;
    let body = ec2_token_request_body(&cred.access, &cred.secret, None, None)?;
    let (status, subject_token, response) =
        post_ec2_token_extract(Some(&admin_token().await?), body).await?;
    assert_eq!(status, StatusCode::OK, "response: {response}");
    let token = subject_token.ok_or_eyre("token must be issued")?;
    Ok((member, cred, token))
}

#[tokio::test]
async fn test_ec2_token_rejected_on_regular_endpoint() -> Result<()> {
    let admin = admin_session().await?;
    let (member, cred, token) = issue_ec2_token(&admin).await?;

    // This endpoint is owner-accessible, so its result cannot be confused
    // with a policy denial that would also reject an ordinary member token.
    let shown = get_ec2_credential(&member.session, &member.user.id, &cred.access).await?;
    assert_eq!(shown.access, cred.access);

    // #1071 (a62c3758): a token minted at /v3/ec2tokens exists only for
    // Swift and must be rejected by the auth extractor everywhere else.
    let path = format!(
        "v3/users/{}/credentials/OS-EC2/{}",
        member.user.id, cred.access
    );
    let rsp = raw_request(http::Method::GET, &path, Some(&token), None).await?;
    assert_eq!(
        rsp.status(),
        StatusCode::UNAUTHORIZED,
        "the auth extractor must reject an EC2-issued token before owner policy runs"
    );

    cleanup(&admin, member, &cred).await?;
    Ok(())
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
    assert_eq!(
        rsp.status(),
        StatusCode::OK,
        "an EC2-issued token must still validate at GET /v3/auth/tokens"
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

    // Reauthentication must preserve the immutable EC2 method marker rather
    // than laundering the token into an ordinary project-scoped bearer.
    let reissued = tc
        .token
        .as_ref()
        .ok_or_eyre("token-from-token reauth must return a token")?
        .expose_secret()
        .to_string();
    let path = format!(
        "v3/users/{}/credentials/OS-EC2/{}",
        member.user.id, cred.access
    );
    let rsp = raw_request(http::Method::GET, &path, Some(&reissued), None).await?;
    assert_eq!(
        rsp.status(),
        StatusCode::UNAUTHORIZED,
        "reauthentication must preserve the EC2 bearer restriction"
    );

    cleanup(&admin, member, &cred).await?;
    Ok(())
}
