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
//! Token restriction CRUD authorization matrix (issue #993).
//!
//! | endpoint                                | 2xx                     | 403                 | 401                   |
//! |-----------------------------------------|-------------------------|---------------------|-----------------------|
//! | POST   /v4/tokens/restrictions          | `create_success_admin`  | `create_forbidden`  | `create_unauthorized` |
//! | GET    /v4/tokens/restrictions/{id}     | `show_success_admin`    | `show_forbidden`    | `show_unauthorized`   |
//! | GET    /v4/tokens/restrictions          | `list_success_admin`    | `list_forbidden`    | `list_unauthorized`   |
//! | PUT    /v4/tokens/restrictions/{id}     | `update_success_admin`  | `update_forbidden`  | `update_unauthorized` |
//! | DELETE /v4/tokens/restrictions/{id}     | `delete_success_admin`  | `delete_forbidden`  | `delete_unauthorized` |
//!
//! This retires the last unreferenced helper module in `test_api`.
//!
//! **Positive coverage is deliberately admin-only.**
//! `policy/token/restriction/{create,update,delete}.rego` each carry a
//! `member` self-service rule of the shape
//!
//! ```text
//! allow if {
//!     "member" in input.credentials.roles
//!     input.target.restriction.user_id != null
//!     input.credentials.user_id == input.target.restriction.user_id
//! }
//! ```
//!
//! which is **not** bound to `domain_id`. A manual probe against a live
//! server confirmed a project-scoped `member` in `default` can create a
//! self-owned restriction carrying a *foreign* `domain_id` and receive
//! `201` — the sibling `violation` rule for `foreign_token_restriction`
//! does not gate `allow`. Asserting that as expected behaviour would pin it
//! into the test suite before a maintainer has confirmed it is intended, so
//! no test here exercises the member self-service path in any direction.
//!
//! Every 403 fixture is therefore a project-scoped `member` acting on a
//! restriction it does **not** own, which every rule denies regardless of
//! how that question is resolved:
//!
//! - `create`: the payload's `user_id` is another user's.
//! - `show`: needs `admin`, or `manager` plus `own_token_restriction`, which
//!   requires the `credentials.domain_id` only a domain-scoped token carries.
//! - `list`: allows bare `manager`, so the fixture is a `member`.
//! - `update`/`delete`: the stored restriction's `user_id` is another user's.

use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::v4::token_restriction::{
    TokenRestrictionCreate, TokenRestrictionUpdate,
};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::ProjectScopedUser;
use test_api::guard::ResourceGuard;
use test_api::token_restriction::*;

const DOMAIN: &str = "default";

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

/// A restriction owned by `user_id`, or unowned when `None`.
fn restriction_create(user_id: Option<&str>) -> TokenRestrictionCreate {
    TokenRestrictionCreate {
        allow_renew: true,
        allow_rescope: true,
        domain_id: DOMAIN.to_string(),
        project_id: None,
        user_id: user_id.map(ToString::to_string),
        roles: Vec::new(),
    }
}

/// A project-scoped `member` — holds `member`/`reader`, never `manager`,
/// never a domain scope.
async fn member(admin: &Arc<AsyncOpenStack>) -> Result<ProjectScopedUser> {
    ProjectScopedUser::provision(admin, DOMAIN, "member").await
}

// --- create -------------------------------------------------------------

#[tokio::test]
async fn test_restriction_create_success_admin() -> Result<()> {
    let admin = admin_session().await?;

    let restriction = create_token_restriction(&admin, restriction_create(None)).await?;
    assert_eq!(restriction.domain_id, DOMAIN);
    assert!(restriction.allow_renew);
    assert!(restriction.allow_rescope);
    assert!(
        !restriction.id.is_empty(),
        "created restriction needs an id"
    );

    restriction.delete().await?;
    Ok(())
}

/// A `member` creating a restriction bound to **another** user — denied by
/// every rule, including the self-service one.
#[tokio::test]
async fn test_restriction_create_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let other = member(&admin).await?;

    assert_forbidden(
        create_token_restriction(&actor.session, restriction_create(Some(&other.user.id))).await,
        "a member must not create a token restriction bound to another user",
    );

    actor.cleanup().await?;
    other.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_restriction_create_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        "v4/tokens/restrictions",
        Some("invalid-token"),
        Some(serde_json::json!({"restriction": {
            "allow_renew": true,
            "allow_rescope": true,
            "domain_id": DOMAIN,
            "roles": [],
        }})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- show ---------------------------------------------------------------

#[tokio::test]
async fn test_restriction_show_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let restriction = create_token_restriction(&admin, restriction_create(None)).await?;

    let shown = get_token_restriction(&admin, &restriction.id).await?;
    assert_eq!(shown.id, restriction.id);
    assert_eq!(shown.domain_id, DOMAIN);

    restriction.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_restriction_show_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let restriction = create_token_restriction(&admin, restriction_create(None)).await?;

    assert_forbidden(
        get_token_restriction(&actor.session, &restriction.id).await,
        "a project-scoped member must not read a token restriction it does not own",
    );

    restriction.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_restriction_show_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/tokens/restrictions/some-id",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- list ---------------------------------------------------------------

#[tokio::test]
async fn test_restriction_list_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let restriction = create_token_restriction(&admin, restriction_create(None)).await?;

    let listed = list_token_restrictions(
        &admin,
        TokenRestrictionListRequest {
            domain_id: Some(DOMAIN.to_string()),
            ..Default::default()
        },
    )
    .await?;
    assert!(
        listed.iter().any(|entry| entry.id == restriction.id),
        "the domain listing must contain the created restriction"
    );

    restriction.delete().await?;
    Ok(())
}

/// `policy/token/restriction/list.rego` allows bare `manager`, so the denial
/// fixture must be a `member`.
#[tokio::test]
async fn test_restriction_list_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;

    assert_forbidden(
        list_token_restrictions(
            &actor.session,
            TokenRestrictionListRequest {
                domain_id: Some(DOMAIN.to_string()),
                ..Default::default()
            },
        )
        .await,
        "a project-scoped member must not list a domain's token restrictions",
    );

    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_restriction_list_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/tokens/restrictions",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- update -------------------------------------------------------------

#[tokio::test]
async fn test_restriction_update_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let restriction = create_token_restriction(&admin, restriction_create(None)).await?;

    let updated = update_token_restriction(
        &admin,
        &restriction.id,
        TokenRestrictionUpdate {
            allow_renew: Some(false),
            allow_rescope: Some(false),
            project_id: None,
            user_id: None,
            roles: None,
        },
    )
    .await?;
    assert_eq!(updated.id, restriction.id);
    assert!(!updated.allow_renew);
    assert!(!updated.allow_rescope);

    // Durable, not just echoed back.
    let shown = get_token_restriction(&admin, &restriction.id).await?;
    assert!(!shown.allow_renew);

    restriction.delete().await?;
    Ok(())
}

/// The stored restriction is bound to another user, so the `member`
/// self-service rule cannot apply.
#[tokio::test]
async fn test_restriction_update_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let other = member(&admin).await?;
    let restriction =
        create_token_restriction(&admin, restriction_create(Some(&other.user.id))).await?;

    assert_forbidden(
        update_token_restriction(
            &actor.session,
            &restriction.id,
            TokenRestrictionUpdate {
                allow_renew: Some(false),
                allow_rescope: None,
                project_id: None,
                user_id: None,
                roles: None,
            },
        )
        .await,
        "a member must not update a token restriction bound to another user",
    );

    restriction.delete().await?;
    actor.cleanup().await?;
    other.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_restriction_update_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::PUT,
        "v4/tokens/restrictions/some-id",
        Some("invalid-token"),
        Some(serde_json::json!({"restriction": {"allow_renew": false}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- delete -------------------------------------------------------------

#[tokio::test]
async fn test_restriction_delete_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    // `into_inner`: delete is the subject here, so the guard must not also
    // delete.
    let restriction = create_token_restriction(&admin, restriction_create(None))
        .await?
        .into_inner();

    delete_token_restriction(&admin, &restriction.id).await?;

    let listed = list_token_restrictions(
        &admin,
        TokenRestrictionListRequest {
            domain_id: Some(DOMAIN.to_string()),
            ..Default::default()
        },
    )
    .await?;
    assert!(
        !listed.iter().any(|entry| entry.id == restriction.id),
        "a deleted restriction must no longer be listed"
    );
    Ok(())
}

#[tokio::test]
async fn test_restriction_delete_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let other = member(&admin).await?;
    let restriction =
        create_token_restriction(&admin, restriction_create(Some(&other.user.id))).await?;

    assert_forbidden(
        delete_token_restriction(&actor.session, &restriction.id).await,
        "a member must not delete a token restriction bound to another user",
    );

    // Still there — the denial was enforced before any mutation.
    assert_eq!(
        get_token_restriction(&admin, &restriction.id).await?.id,
        restriction.id
    );

    restriction.delete().await?;
    actor.cleanup().await?;
    other.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_restriction_delete_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v4/tokens/restrictions/some-id",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
