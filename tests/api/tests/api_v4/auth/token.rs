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
//! `/v4/auth/tokens` authorization matrix (issue #993).
//!
//! `crates/keystone/src/api/v4/auth/token/mod.rs` re-mounts the v3 router,
//! but the v3 live suite covers only successful flows, so the denial and
//! invalid-auth cases are built here.
//!
//! | endpoint                | 2xx                                            | 403                     | 401 / 4xx                    |
//! |-------------------------|------------------------------------------------|-------------------------|------------------------------|
//! | POST   /v4/auth/tokens  | `create_success_password`, `create_success_scoped` | —                    | `create_bad_credentials`     |
//! | GET    /v4/auth/tokens  | `show_success_admin`, `show_success_own_token`  | `show_forbidden_other`  | `show_unauthorized`          |
//! | DELETE /v4/auth/tokens  | `revoke_success_own_token`                     | `revoke_forbidden_other`| `revoke_unauthorized`        |
//!
//! `POST` is the authentication endpoint itself and enforces no policy — it
//! has no 403 case; a bad password is rejected by authentication, not
//! authorization.
//!
//! `policy/auth/token/{show,revoke}.rego` allow `admin`, `service`, a
//! system-scoped `reader`, or `identity.token_subject` — the caller
//! inspecting *their own* token. That last rule gives genuine non-admin 2xx
//! coverage, and a plain user reaching for someone else's token is the 403.
//!
//! v3/v4 agreement is asserted over **normalized semantic fields** (user id,
//! user name, project id, sorted role names), never whole-response equality:
//! two independently issued tokens necessarily differ in `issued_at`,
//! `expires_at` and the opaque token value.

use std::env;
use std::sync::Arc;

use eyre::{OptionExt, Result};
use reqwest::StatusCode;

use openstack_keystone_api_types::scope::{
    DomainBuilder, Scope, ScopeProjectBuilder, System as ScopeSystem,
};
use openstack_keystone_api_types::v3::auth::token::{IdentityBuilder, TokenResponse};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::auth::token_v4::*;
use test_api::common::{get_password_auth, raw_request};
use test_api::fixtures::{
    FIXTURE_PASSWORD, ProjectScopedUser, cleanup_project_scoped_users, warn_on_cleanup_failure,
};

const DOMAIN: &str = "default";

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

fn admin_password() -> String {
    env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or_else(|_| "password".to_string())
}

/// A password `Identity` for the given user in [`DOMAIN`].
fn password_identity(
    name: &str,
    password: &str,
) -> Result<openstack_keystone_api_types::v3::auth::token::Identity> {
    Ok(IdentityBuilder::default()
        .methods(vec!["password".into()])
        .password(get_password_auth(name, password, DOMAIN)?)
        .build()?)
}

/// Authenticate a fixture user through `/v4` and return their token secret.
async fn fixture_token(fixture: &ProjectScopedUser) -> Result<secrecy::SecretString> {
    let scope = Scope::Project(
        ScopeProjectBuilder::default()
            .id(fixture.project.id.clone())
            .domain(DomainBuilder::default().id(DOMAIN).build()?)
            .build()?,
    );
    let (_, token) = authenticate_v4(
        password_identity(&fixture.user.name, FIXTURE_PASSWORD)?,
        Some(scope),
    )
    .await?;
    Ok(token)
}

/// The admin's own `/v4`-issued, system-scoped token.
async fn admin_token() -> Result<secrecy::SecretString> {
    let (_, token) = authenticate_v4(
        password_identity("admin", &admin_password())?,
        Some(Scope::System(ScopeSystem { all: Some(true) })),
    )
    .await?;
    Ok(token)
}

/// Two independent member users; `a` will reach for `b`'s token. Releases
/// `a` when `b` fails to provision, so a mid-setup error leaves nothing
/// behind on the live server.
async fn two_members(
    admin: &Arc<AsyncOpenStack>,
) -> Result<(ProjectScopedUser, ProjectScopedUser)> {
    let a = ProjectScopedUser::provision(admin, DOMAIN, "member").await?;
    match ProjectScopedUser::provision(admin, DOMAIN, "member").await {
        Ok(b) => Ok((a, b)),
        Err(error) => {
            warn_on_cleanup_failure("member fixture", a.cleanup().await);
            Err(error)
        }
    }
}

// --- POST /v4/auth/tokens -----------------------------------------------

#[tokio::test]
async fn test_v4_auth_token_create_success_password() -> Result<()> {
    let rsp = authenticate_v4_raw(password_identity("admin", &admin_password())?, None).await?;

    assert_eq!(rsp.status(), StatusCode::CREATED);
    assert!(
        rsp.headers().contains_key("x-subject-token"),
        "a successful authentication must return the token in X-Subject-Token"
    );

    let body: TokenResponse = rsp.json().await?;
    assert_eq!(body.token.user.name.as_deref(), Some("admin"));
    assert!(
        body.token.project.is_none(),
        "an unscoped request must not yield a project-scoped token"
    );
    Ok(())
}

#[tokio::test]
async fn test_v4_auth_token_create_success_scoped() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, DOMAIN, "member").await?;
    let scope = Scope::Project(
        ScopeProjectBuilder::default()
            .id(fixture.project.id.clone())
            .domain(DomainBuilder::default().id(DOMAIN).build()?)
            .build()?,
    );

    let (body, _token) = authenticate_v4(
        password_identity(&fixture.user.name, FIXTURE_PASSWORD)?,
        Some(scope),
    )
    .await?;

    let project = body
        .token
        .project
        .as_ref()
        .ok_or_eyre("a project-scoped request must yield a project-scoped token")?;
    assert_eq!(project.id, fixture.project.id);
    assert_eq!(body.token.user.id, fixture.user.id);
    assert!(
        body.token
            .roles
            .iter()
            .flatten()
            .any(|role| role.name == "member"),
        "the token must carry the granted `member` role, got: {:?}",
        body.token.roles
    );

    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_auth_token_create_bad_credentials() -> Result<()> {
    let rsp = authenticate_v4_raw(
        password_identity("admin", "definitely-not-the-password")?,
        None,
    )
    .await?;
    assert_unauthorized(
        rsp.error_for_status(),
        "a wrong password must be rejected by authentication",
    );
    Ok(())
}

/// The `/v4` and `/v3` token endpoints are the same handler, so the issued
/// tokens must describe the same authorization. Compared field-by-field on
/// normalized values — never as whole responses, which carry per-issue
/// timestamps.
#[tokio::test]
async fn test_v4_auth_token_matches_v3_semantics() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, DOMAIN, "member").await?;
    let scope = Scope::Project(
        ScopeProjectBuilder::default()
            .id(fixture.project.id.clone())
            .domain(DomainBuilder::default().id(DOMAIN).build()?)
            .build()?,
    );
    let identity = password_identity(&fixture.user.name, FIXTURE_PASSWORD)?;

    let (v4_body, _) = authenticate_v4(identity.clone(), Some(scope.clone())).await?;

    let base_url: url::Url = env::var("KEYSTONE_URL")?.parse()?;
    let v3_rsp = test_api::common::http_client()
        .post(base_url.join("v3/auth/tokens")?)
        .json(&serde_json::json!({
            "auth": { "identity": identity, "scope": scope }
        }))
        .send()
        .await?;
    assert_eq!(v3_rsp.status(), StatusCode::CREATED);
    let v3_body: TokenResponse = v3_rsp.json().await?;

    assert_eq!(v4_body.token.user.id, v3_body.token.user.id);
    assert_eq!(v4_body.token.user.name, v3_body.token.user.name);
    assert_eq!(
        v4_body.token.project.as_ref().map(|p| &p.id),
        v3_body.token.project.as_ref().map(|p| &p.id),
    );

    let role_names = |body: &TokenResponse| {
        let mut names: Vec<String> = body
            .token
            .roles
            .iter()
            .flatten()
            .map(|role| role.name.clone())
            .collect();
        names.sort();
        names
    };
    assert_eq!(role_names(&v4_body), role_names(&v3_body));

    fixture.cleanup().await?;
    Ok(())
}

// --- GET /v4/auth/tokens ------------------------------------------------

#[tokio::test]
async fn test_v4_auth_token_show_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, DOMAIN, "member").await?;
    let subject = fixture_token(&fixture).await?;
    let caller = admin_token().await?;

    let rsp = validate_token_v4(&caller, &subject).await?;
    assert_eq!(rsp.status(), StatusCode::OK);

    let body: TokenResponse = rsp.json().await?;
    assert_eq!(body.token.user.id, fixture.user.id);

    fixture.cleanup().await?;
    Ok(())
}

/// `identity.token_subject`: a plain user may validate their own token.
#[tokio::test]
async fn test_v4_auth_token_show_success_own_token() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, DOMAIN, "member").await?;
    let token = fixture_token(&fixture).await?;

    let rsp = validate_token_v4(&token, &token).await?;
    assert_eq!(rsp.status(), StatusCode::OK);

    let body: TokenResponse = rsp.json().await?;
    assert_eq!(body.token.user.id, fixture.user.id);

    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_auth_token_show_forbidden_other() -> Result<()> {
    let admin = admin_session().await?;
    let (a, b) = two_members(&admin).await?;
    let caller = fixture_token(&a).await?;
    let subject = fixture_token(&b).await?;

    let rsp = validate_token_v4(&caller, &subject).await?;
    assert_forbidden(
        rsp.error_for_status(),
        "a member must not validate another user's token",
    );

    cleanup_project_scoped_users([a, b]).await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_auth_token_show_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/auth/tokens",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- DELETE /v4/auth/tokens ---------------------------------------------

#[tokio::test]
async fn test_v4_auth_token_revoke_success_own_token() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, DOMAIN, "member").await?;
    let token = fixture_token(&fixture).await?;

    let rsp = revoke_token_v4(&token, &token).await?;
    assert!(
        rsp.status().is_success(),
        "revoking one's own token must succeed, got {}",
        rsp.status()
    );

    // The revoked token no longer authenticates.
    let after = validate_token_v4(&token, &token).await?;
    assert_ne!(
        after.status(),
        StatusCode::OK,
        "a revoked token must not validate"
    );

    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_auth_token_revoke_forbidden_other() -> Result<()> {
    let admin = admin_session().await?;
    let (a, b) = two_members(&admin).await?;
    let caller = fixture_token(&a).await?;
    let subject = fixture_token(&b).await?;

    let rsp = revoke_token_v4(&caller, &subject).await?;
    assert_forbidden(
        rsp.error_for_status(),
        "a member must not revoke another user's token",
    );

    // Still valid — the denial was enforced before any mutation.
    let still = validate_token_v4(&subject, &subject).await?;
    assert_eq!(still.status(), StatusCode::OK);

    cleanup_project_scoped_users([a, b]).await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_auth_token_revoke_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v4/auth/tokens",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
