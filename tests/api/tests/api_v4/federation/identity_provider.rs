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
//! Federation identity provider CRUD authorization matrix (issue #993).
//!
//! The issue places this suite under `api_v3`, but federation is mounted
//! **only** on v4 (`crates/keystone/src/api/v4/mod.rs` nests
//! `crate::federation::api` at `/v4/federation`; the v3 router has no
//! federation entry), so it lives here. The helper module was previously
//! reachable only from the SCIM realm and SCIM v2 suites, which use it to
//! provision a realm's required `idp_id`.
//!
//! | endpoint                                       | 2xx                                            | 403                            | 401                   |
//! |------------------------------------------------|------------------------------------------------|--------------------------------|-----------------------|
//! | POST   /v4/federation/identity_providers       | `create_success_admin`                         | `create_forbidden_member`      | `create_unauthorized` |
//! | GET    /v4/federation/identity_providers/{id}  | `show_success_admin`                           | `show_forbidden_member`        | `show_unauthorized`   |
//! | GET    /v4/federation/identity_providers       | `list_success_admin`, `list_success_member_unfiltered` | `list_forbidden_member_domain_filter` | `list_unauthorized` |
//! | PUT    /v4/federation/identity_providers/{id}  | `update_success_admin`                         | `update_forbidden_member`      | `update_unauthorized` |
//! | DELETE /v4/federation/identity_providers/{id}  | `delete_success_admin`                         | `delete_forbidden_member`      | `delete_unauthorized` |
//!
//! `policy/federation/identity_provider/*.rego` allows `admin`, or `manager`
//! (create/update/delete) / `reader` (show/list) paired with
//! `common_federation.own_idp`, which needs the `credentials.domain_id` only
//! a domain-scoped token carries. No such token is provisionable, so the 403
//! fixture is a project-scoped `member`.
//!
//! `list` is the exception and gets a genuine non-admin 2xx. Its policy input
//! puts the *query parameters* in `input.target.identity_provider`, so an
//! unfiltered list has no `domain_id` and satisfies
//! `common_federation.global_idp`, which `reader` may see. Adding any
//! `domain_id` filter moves it onto the `own_idp` path and denies the same
//! caller — which is what the 403 case asserts.

use std::sync::Arc;

use eyre::Result;
use secrecy::SecretString;
use uuid::Uuid;

use openstack_keystone_api_types::federation::{
    IdentityProviderCreate, IdentityProviderCreateBuilder, IdentityProviderUpdateBuilder,
};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::common::raw_request;
use test_api::federation::identity_provider::*;
use test_api::fixtures::ProjectScopedUser;
use test_api::guard::ResourceGuard;

const DOMAIN: &str = "default";

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

fn idp_create() -> Result<IdentityProviderCreate> {
    Ok(IdentityProviderCreateBuilder::default()
        .name(format!("v4-idp-{}", Uuid::new_v4().simple()))
        .domain_id(DOMAIN)
        .enabled(true)
        .build()?)
}

/// A project-scoped `member` — implies `reader`, never holds a domain scope.
async fn member(admin: &Arc<AsyncOpenStack>) -> Result<ProjectScopedUser> {
    ProjectScopedUser::provision(admin, DOMAIN, "member").await
}

// --- create -------------------------------------------------------------

#[tokio::test]
async fn test_idp_create_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let payload = idp_create()?;
    let name = payload.name.clone();

    let idp = create_identity_provider(&admin, payload).await?;
    assert_eq!(idp.name, name);
    assert_eq!(idp.domain_id.as_deref(), Some(DOMAIN));
    assert!(idp.enabled);
    assert!(!idp.id.is_empty(), "created IDP must have an id");

    idp.delete().await?;
    Ok(())
}

/// `oidc_client_secret` is write-only (ADR: "never returned"). Asserted
/// against raw JSON — `IdentityProvider` has no such field at all, so a
/// typed decode would drop a leaked secret silently.
#[tokio::test]
async fn test_idp_create_withholds_client_secret() -> Result<()> {
    let admin = admin_session().await?;
    let payload = IdentityProviderCreateBuilder::default()
        .name(format!("v4-idp-{}", Uuid::new_v4().simple()))
        .domain_id(DOMAIN)
        .enabled(true)
        .oidc_client_id("test-client")
        .oidc_client_secret(SecretString::from("super-secret-value"))
        .build()?;

    let idp = create_identity_provider(&admin, payload).await?;

    let shown = get_identity_provider_raw(&admin, &idp.id)
        .await?
        .to_string();
    for field in ["oidc_client_secret", "super-secret-value"] {
        assert!(
            !shown.contains(field),
            "the IDP representation must not expose `{field}`; body was: {shown}"
        );
    }
    // The non-secret half of the pair is still returned.
    assert_eq!(
        get_identity_provider(&admin, &idp.id)
            .await?
            .oidc_client_id
            .as_deref(),
        Some("test-client")
    );

    idp.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_idp_create_forbidden_member() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;

    assert_forbidden(
        create_identity_provider(&actor.session, idp_create()?).await,
        "a project-scoped member must not create identity providers",
    );

    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_idp_create_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        "v4/federation/identity_providers",
        Some("invalid-token"),
        Some(serde_json::json!({"identity_provider": {"name": "nope", "domain_id": DOMAIN}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- show ---------------------------------------------------------------

#[tokio::test]
async fn test_idp_show_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let idp = create_identity_provider(&admin, idp_create()?).await?;

    let shown = get_identity_provider(&admin, &idp.id).await?;
    assert_eq!(shown.id, idp.id);
    assert_eq!(shown.name, idp.name);
    assert_eq!(shown.domain_id.as_deref(), Some(DOMAIN));

    idp.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_idp_show_forbidden_member() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let idp = create_identity_provider(&admin, idp_create()?).await?;

    assert_forbidden(
        get_identity_provider(&actor.session, &idp.id).await,
        "a project-scoped member must not read a domain-owned identity provider",
    );

    idp.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_idp_show_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/federation/identity_providers/some-idp",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- list ---------------------------------------------------------------

#[tokio::test]
async fn test_idp_list_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let idp = create_identity_provider(&admin, idp_create()?).await?;

    let by_name = list_identity_providers(
        &admin,
        IdentityProviderListRequest {
            name: Some(idp.name.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(by_name.len(), 1, "name filter must match exactly one IDP");
    assert_eq!(by_name[0].id, idp.id);

    let by_domain = list_identity_providers(
        &admin,
        IdentityProviderListRequest {
            domain_id: Some(DOMAIN.to_string()),
            ..Default::default()
        },
    )
    .await?;
    assert!(
        by_domain.iter().any(|entry| entry.id == idp.id),
        "the domain listing must contain the created IDP"
    );

    idp.delete().await?;
    Ok(())
}

/// An unfiltered list carries no `domain_id` in the policy input, so it
/// resolves through `global_idp` and any `reader` — here a project-scoped
/// `member` — is allowed.
#[tokio::test]
async fn test_idp_list_success_member_unfiltered() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let idp = create_identity_provider(&admin, idp_create()?).await?;

    let listed =
        list_identity_providers(&actor.session, IdentityProviderListRequest::default()).await?;
    assert!(
        listed.iter().any(|entry| entry.id == idp.id),
        "an unfiltered list must be readable by a `reader` and contain the IDP"
    );

    idp.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

/// Adding a `domain_id` filter moves the same caller onto the `own_idp`
/// path, which needs a domain scope.
#[tokio::test]
async fn test_idp_list_forbidden_member_domain_filter() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;

    assert_forbidden(
        list_identity_providers(
            &actor.session,
            IdentityProviderListRequest {
                domain_id: Some(DOMAIN.to_string()),
                ..Default::default()
            },
        )
        .await,
        "a domain-filtered IDP list requires `reader` with a genuine domain scope",
    );

    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_idp_list_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/federation/identity_providers",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- update -------------------------------------------------------------

#[tokio::test]
async fn test_idp_update_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let idp = create_identity_provider(&admin, idp_create()?).await?;
    let renamed = format!("{}-renamed", idp.name);

    let updated = update_identity_provider(
        &admin,
        &idp.id,
        IdentityProviderUpdateBuilder::default()
            .name(renamed.clone())
            .enabled(false)
            .build()?,
    )
    .await?;
    assert_eq!(updated.id, idp.id);
    assert_eq!(updated.name, renamed);
    assert!(!updated.enabled, "update must disable the IDP");

    // Durable, not just echoed back.
    let shown = get_identity_provider(&admin, &idp.id).await?;
    assert_eq!(shown.name, renamed);
    assert!(!shown.enabled);

    idp.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_idp_update_forbidden_member() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let idp = create_identity_provider(&admin, idp_create()?).await?;

    assert_forbidden(
        update_identity_provider(
            &actor.session,
            &idp.id,
            // `name` has no builder default, so it must be supplied even for
            // a denial case.
            IdentityProviderUpdateBuilder::default()
                .name(idp.name.clone())
                .enabled(false)
                .build()?,
        )
        .await,
        "a project-scoped member must not update an identity provider",
    );

    idp.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_idp_update_unauthorized() -> Result<()> {
    // PUT, not PATCH: v4 update handlers declare `put`.
    let rsp = raw_request(
        http::Method::PUT,
        "v4/federation/identity_providers/some-idp",
        Some("invalid-token"),
        Some(serde_json::json!({"identity_provider": {"enabled": false}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- delete -------------------------------------------------------------

#[tokio::test]
async fn test_idp_delete_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    // `into_inner`: delete is the subject here, so the guard must not also
    // delete.
    let idp = create_identity_provider(&admin, idp_create()?)
        .await?
        .into_inner();

    delete_identity_provider(&admin, &idp.id).await?;

    let listed = list_identity_providers(
        &admin,
        IdentityProviderListRequest {
            name: Some(idp.name.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert!(listed.is_empty(), "a deleted IDP must not be listed");
    Ok(())
}

#[tokio::test]
async fn test_idp_delete_forbidden_member() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let idp = create_identity_provider(&admin, idp_create()?).await?;

    assert_forbidden(
        delete_identity_provider(&actor.session, &idp.id).await,
        "a project-scoped member must not delete an identity provider",
    );

    // Still there — the denial was enforced before any mutation.
    assert_eq!(get_identity_provider(&admin, &idp.id).await?.id, idp.id);

    idp.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_idp_delete_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v4/federation/identity_providers/some-idp",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
