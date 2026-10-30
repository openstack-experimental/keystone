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
//! v4 role assignment authorization matrix (issue #993).
//!
//! `crates/keystone/src/api/v4/role_assignment/mod.rs` re-mounts the v3
//! v4 authorization matrix for the role assignment endpoints that bind a
//! `user`/`group` to a `domain`/`project`:
//!
//! | endpoint                                            | module            |
//! |-----------------------------------------------------|-------------------|
//! | `/v4/domains/{d}/users/{u}/roles[/{r}]`             | `domain_user`     |
//! | `/v4/domains/{d}/groups/{g}/roles[/{r}]`            | `domain_group`    |
//! | `/v4/projects/{p}/groups/{g}/roles[/{r}]`           | `project_group`   |
//!
//! Every operation (`PUT` grant, `HEAD` check, `GET` list, `DELETE` revoke)
//! gets a 2xx case for `admin`, a 403 case for a project-scoped `member`,
//! a 401 case for an invalid token and the relevant 404 cases. `check` and
//! `list` additionally get a 2xx case for a system-scoped `reader`
//! (`credentials.system == "all"`).
//!
//! Domain-scoped `manager` rules cannot be exercised here: no fixture
//! provisions a domain-scoped token (see `role_assignment.rs`).

use std::sync::Arc;

use eyre::{OptionExt, Result};
use uuid::Uuid;

use openstack_keystone_api_types::v3::domain::Domain;
use openstack_keystone_api_types::v3::group::{Group, GroupCreateBuilder};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_status, assert_unauthorized};
use test_api::assignment::v4::*;
use test_api::common::raw_request;
use test_api::fixtures::{ProjectScopedUser, SystemScopedUser};
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::identity::group::create_group;
use test_api::resource::domain::create_test_domain;
use test_api::role::list_roles;

const DOMAIN: &str = "default";

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

async fn role_id(admin: &Arc<AsyncOpenStack>, name: &str) -> Result<String> {
    Ok(list_roles(admin)
        .await?
        .into_iter()
        .find(|role| role.name == name)
        .ok_or_eyre(format!("bootstrap `{name}` role must exist"))?
        .id)
}

async fn member(admin: &Arc<AsyncOpenStack>) -> Result<ProjectScopedUser> {
    ProjectScopedUser::provision(admin, DOMAIN, "member").await
}

/// Scope + actor pair under test with everything needed to clean it up.
///
/// `holder` provides the user (actor `user`) and the project (scope
/// `project`); a fresh domain / group are created on demand.
struct Fixture {
    scope: &'static str,
    actor: &'static str,
    scope_id: String,
    actor_id: String,
    holder: ProjectScopedUser,
    domain: Option<AsyncResourceGuard<Domain>>,
    group: Option<AsyncResourceGuard<Group>>,
}

impl Fixture {
    async fn provision(
        admin: &Arc<AsyncOpenStack>,
        scope: &'static str,
        actor: &'static str,
    ) -> Result<Self> {
        let holder = member(admin).await?;
        let domain = if scope == "domain" {
            Some(create_test_domain(admin).await?)
        } else {
            None
        };
        let group = if actor == "group" {
            Some(
                create_group(
                    admin,
                    GroupCreateBuilder::default()
                        .name(format!("as-grp-{}", Uuid::new_v4().simple()))
                        .domain_id(DOMAIN)
                        .build()?,
                )
                .await?,
            )
        } else {
            None
        };
        let scope_id = match &domain {
            Some(d) => d.id.clone(),
            None => holder.project.id.clone(),
        };
        let actor_id = match &group {
            Some(g) => g.id.clone(),
            None => holder.user.id.clone(),
        };
        Ok(Self {
            scope,
            actor,
            scope_id,
            actor_id,
            holder,
            domain,
            group,
        })
    }

    async fn grant(&self, client: &Arc<AsyncOpenStack>, role: &str) -> Result<()> {
        grant_actor_role_v4(
            client,
            self.scope,
            &self.scope_id,
            self.actor,
            &self.actor_id,
            role,
        )
        .await
    }

    async fn check(&self, client: &Arc<AsyncOpenStack>, role: &str) -> Result<()> {
        check_actor_role_v4(
            client,
            self.scope,
            &self.scope_id,
            self.actor,
            &self.actor_id,
            role,
        )
        .await
    }

    async fn revoke(&self, client: &Arc<AsyncOpenStack>, role: &str) -> Result<()> {
        revoke_actor_role_v4(
            client,
            self.scope,
            &self.scope_id,
            self.actor,
            &self.actor_id,
            role,
        )
        .await
    }

    async fn list(
        &self,
        client: &Arc<AsyncOpenStack>,
    ) -> Result<Vec<openstack_keystone_api_types::v3::role_assignment::Role>> {
        list_actor_roles_v4(
            client,
            self.scope,
            &self.scope_id,
            self.actor,
            &self.actor_id,
        )
        .await
    }

    /// Remove the fixture resources; a domain is disabled+deleted by its
    /// guard which also drops the grants made on it.
    async fn cleanup(self) -> Result<()> {
        if let Some(group) = self.group {
            group.delete().await?;
        }
        if let Some(domain) = self.domain {
            domain.delete().await?;
        }
        self.holder.cleanup().await
    }
}

macro_rules! actor_scope_tests {
    ($mod_name:ident, $scope:literal, $actor:literal) => {
        mod $mod_name {
            use super::*;

            const SCOPE: &str = $scope;
            const ACTOR: &str = $actor;

            fn url(role: Option<&str>) -> String {
                let base = format!("v4/{SCOPE}s/s1/{ACTOR}s/a1/roles");
                match role {
                    Some(r) => format!("{base}/{r}"),
                    None => base,
                }
            }

            // --- grant -----------------------------------------------

            #[tokio::test]
            async fn test_grant_success_admin() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let reader = role_id(&admin, "reader").await?;

                fx.grant(&admin, &reader).await?;
                // The grant is observable through the check endpoint.
                fx.check(&admin, &reader).await?;

                fx.revoke(&admin, &reader).await?;
                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_grant_forbidden() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let actor = member(&admin).await?;
                let reader = role_id(&admin, "reader").await?;

                assert_forbidden(
                    fx.grant(&actor.session, &reader).await,
                    "a project-scoped member must not grant roles",
                );
                // The denial happened before any mutation.
                assert_status(
                    fx.check(&admin, &reader).await,
                    http::StatusCode::NOT_FOUND,
                    "the denied grant must not exist",
                );

                actor.cleanup().await?;
                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_grant_unknown_actor_not_found() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let reader = role_id(&admin, "reader").await?;

                assert_status(
                    grant_actor_role_v4(
                        &admin,
                        SCOPE,
                        &fx.scope_id,
                        ACTOR,
                        &Uuid::new_v4().simple().to_string(),
                        &reader,
                    )
                    .await,
                    http::StatusCode::NOT_FOUND,
                    "an unknown actor must be reported as 404",
                );

                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_grant_unknown_role_not_found() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;

                assert_status(
                    fx.grant(&admin, &Uuid::new_v4().simple().to_string()).await,
                    http::StatusCode::NOT_FOUND,
                    "an unknown role must be reported as 404",
                );

                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_grant_unauthorized() -> Result<()> {
                let rsp = raw_request(
                    http::Method::PUT,
                    &url(Some("r1")),
                    Some("invalid-token"),
                    None,
                )
                .await?;
                assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
                Ok(())
            }

            // --- check -----------------------------------------------

            #[tokio::test]
            async fn test_check_success_admin() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let reader = role_id(&admin, "reader").await?;

                fx.grant(&admin, &reader).await?;
                fx.check(&admin, &reader).await?;

                fx.revoke(&admin, &reader).await?;
                fx.cleanup().await
            }

            /// `reader` with `system == "all"` may check assignments.
            #[tokio::test]
            async fn test_check_success_system_reader() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let actor = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;
                let reader = role_id(&admin, "reader").await?;

                fx.grant(&admin, &reader).await?;
                fx.check(&actor.session, &reader).await?;

                fx.revoke(&admin, &reader).await?;
                actor.cleanup().await?;
                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_check_missing_grant_not_found() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let reader = role_id(&admin, "reader").await?;

                assert_status(
                    fx.check(&admin, &reader).await,
                    http::StatusCode::NOT_FOUND,
                    "an absent grant must be reported as 404",
                );

                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_check_forbidden() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let actor = member(&admin).await?;
                let reader = role_id(&admin, "reader").await?;

                assert_forbidden(
                    fx.check(&actor.session, &reader).await,
                    "a project-scoped member must not check assignments",
                );

                actor.cleanup().await?;
                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_check_unauthorized() -> Result<()> {
                let rsp = raw_request(
                    http::Method::HEAD,
                    &url(Some("r1")),
                    Some("invalid-token"),
                    None,
                )
                .await?;
                assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
                Ok(())
            }

            // --- list ------------------------------------------------

            #[tokio::test]
            async fn test_list_success_admin() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let reader = role_id(&admin, "reader").await?;
                let member_role = role_id(&admin, "member").await?;

                assert!(
                    fx.list(&admin).await?.is_empty(),
                    "a fresh fixture must have no grants"
                );

                fx.grant(&admin, &reader).await?;
                fx.grant(&admin, &member_role).await?;
                let roles = fx.list(&admin).await?;
                assert!(
                    roles.iter().any(|r| r.id == reader)
                        && roles.iter().any(|r| r.id == member_role),
                    "granted roles must be listed, got: {roles:?}"
                );

                fx.revoke(&admin, &reader).await?;
                fx.revoke(&admin, &member_role).await?;
                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_list_success_system_reader() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let actor = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;

                assert!(fx.list(&actor.session).await?.is_empty());

                actor.cleanup().await?;
                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_list_forbidden() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let actor = member(&admin).await?;

                assert_forbidden(
                    fx.list(&actor.session).await,
                    "a project-scoped member must not list assignments",
                );

                actor.cleanup().await?;
                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_list_unauthorized() -> Result<()> {
                let rsp =
                    raw_request(http::Method::GET, &url(None), Some("invalid-token"), None).await?;
                assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
                Ok(())
            }

            // --- revoke ----------------------------------------------

            #[tokio::test]
            async fn test_revoke_success_admin() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let reader = role_id(&admin, "reader").await?;

                fx.grant(&admin, &reader).await?;
                fx.revoke(&admin, &reader).await?;

                assert_status(
                    fx.check(&admin, &reader).await,
                    http::StatusCode::NOT_FOUND,
                    "a revoked grant must be gone",
                );
                assert!(!fx.list(&admin).await?.iter().any(|r| r.id == reader));

                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_revoke_missing_grant_not_found() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let reader = role_id(&admin, "reader").await?;

                assert_status(
                    fx.revoke(&admin, &reader).await,
                    http::StatusCode::NOT_FOUND,
                    "revoking an absent grant must be reported as 404",
                );

                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_revoke_forbidden() -> Result<()> {
                let admin = admin_session().await?;
                let fx = Fixture::provision(&admin, SCOPE, ACTOR).await?;
                let actor = member(&admin).await?;
                let reader = role_id(&admin, "reader").await?;

                fx.grant(&admin, &reader).await?;
                assert_forbidden(
                    fx.revoke(&actor.session, &reader).await,
                    "a project-scoped member must not revoke assignments",
                );
                // Still granted — the denial was enforced before any mutation.
                fx.check(&admin, &reader).await?;

                fx.revoke(&admin, &reader).await?;
                actor.cleanup().await?;
                fx.cleanup().await
            }

            #[tokio::test]
            async fn test_revoke_unauthorized() -> Result<()> {
                let rsp = raw_request(
                    http::Method::DELETE,
                    &url(Some("r1")),
                    Some("invalid-token"),
                    None,
                )
                .await?;
                assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
                Ok(())
            }
        }
    };
}

actor_scope_tests!(domain_user, "domain", "user");
actor_scope_tests!(domain_group, "domain", "group");
actor_scope_tests!(project_group, "project", "group");
