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
//! Reusable live-API fixtures for authorization-matrix tests.

use std::sync::Arc;

use eyre::{OptionExt, Result};
use uuid::Uuid;

use openstack_keystone_api_types::scope::{
    DomainBuilder, Scope, ScopeProjectBuilder, System as ScopeSystem,
};
use openstack_keystone_api_types::v3::project::{Project, ProjectCreateBuilder};
use openstack_keystone_api_types::v3::user::{User, UserCreateBuilder};
use openstack_sdk::AsyncOpenStack;

use crate::assignment::grant::{add_project_grant, add_system_grant};
use crate::common::get_user_session;
use crate::guard::{AsyncResourceGuard, ResourceGuard};
use crate::identity::user::create_user;
use crate::resource::project::create_project;
use crate::role::list_roles;

/// Password used for all fixture users.
pub const FIXTURE_PASSWORD: &str = "fixture-user-password";

/// Report a failed best-effort cleanup without discarding the error that
/// triggered it — the original failure is the one worth diagnosing.
pub fn warn_on_cleanup_failure(what: &str, result: Result<()>) {
    if let Err(error) = result {
        tracing::warn!("failed to clean up {what} after an error: {error:?}");
    }
}

/// A real user provisioned through the live API holding a bootstrap role
/// (e.g. `member` or `manager`) on a fresh project in `domain_id`,
/// authenticated with a **project-scoped** token through the real
/// password-auth path.
///
/// All fixture resources are created by — and cleaned up with — the admin
/// session passed to [`Self::provision`], so cleanup never depends on the
/// underprivileged session.
pub struct ProjectScopedUser {
    /// Project-scoped session authenticated as the fixture user.
    pub session: Arc<AsyncOpenStack>,
    /// The fixture user (guarded; deleted by [`Self::cleanup`]).
    pub user: AsyncResourceGuard<User>,
    /// The fixture project (guarded; deleted by [`Self::cleanup`]).
    pub project: AsyncResourceGuard<Project>,
}

impl ProjectScopedUser {
    /// Provision a user with `role_name` granted on a fresh project in
    /// `domain_id`.
    pub async fn provision(
        admin: &Arc<AsyncOpenStack>,
        domain_id: &str,
        role_name: &str,
    ) -> Result<Self> {
        let unique = Uuid::new_v4().simple().to_string();
        let project_create = ProjectCreateBuilder::default()
            .name(format!("fix-proj-{unique}"))
            .domain_id(domain_id)
            .build()?;
        let user_create = UserCreateBuilder::default()
            .name(format!("fix-usr-{unique}"))
            .domain_id(domain_id)
            .password(FIXTURE_PASSWORD)
            .enabled(true)
            .build()?;

        let project = create_project(admin, project_create).await?;
        let user_result = create_user(admin, user_create).await;
        let user = match user_result {
            Ok(user) => user,
            Err(error) => {
                warn_on_cleanup_failure("fixture project", project.delete().await);
                return Err(error);
            }
        };
        let session_result = async {
            let role = list_roles(admin)
                .await?
                .into_iter()
                .find(|role| role.name == role_name)
                .ok_or_eyre(format!("bootstrap `{role_name}` role must exist"))?;
            add_project_grant(admin, &project.id, &user.id, &role.id).await?;

            let scope = Scope::Project(
                ScopeProjectBuilder::default()
                    .id(project.id.clone())
                    .domain(DomainBuilder::default().id(domain_id).build()?)
                    .build()?,
            );
            get_user_session(&user.name, FIXTURE_PASSWORD, domain_id, Some(&scope)).await
        }
        .await;

        match session_result {
            Ok(session) => Ok(Self {
                session,
                user,
                project,
            }),
            Err(error) => {
                warn_on_cleanup_failure("fixture user", user.delete().await);
                warn_on_cleanup_failure("fixture project", project.delete().await);
                Err(error)
            }
        }
    }

    /// Delete the fixture user and project with the admin session that
    /// created them.
    pub async fn cleanup(self) -> Result<()> {
        let user_cleanup_result = self.user.delete().await;
        let project_cleanup_result = self.project.delete().await;
        user_cleanup_result?;
        project_cleanup_result
    }
}

/// Delete every project-scoped fixture, attempting all cleanups before
/// returning the first error.
pub async fn cleanup_project_scoped_users(
    fixtures: impl IntoIterator<Item = ProjectScopedUser>,
) -> Result<()> {
    let mut first_error = None;
    for fixture in fixtures {
        if let Err(error) = fixture.cleanup().await {
            if first_error.is_none() {
                first_error = Some(error);
            } else {
                tracing::warn!(?error, "additional project-scoped fixture cleanup failed");
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// A real password user holding one role on the system scope and authenticated
/// with a system-scoped token through the live password-auth path.
pub struct SystemScopedUser {
    /// System-scoped session authenticated as the fixture user.
    pub session: Arc<AsyncOpenStack>,
    /// The fixture user, deleted by [`Self::cleanup`].
    pub user: AsyncResourceGuard<User>,
}

impl SystemScopedUser {
    /// Provision a user with `role_name` granted on `system: all`.
    pub async fn provision(
        admin: &Arc<AsyncOpenStack>,
        domain_id: &str,
        role_name: &str,
    ) -> Result<Self> {
        let unique = Uuid::new_v4().simple().to_string();
        let user = create_user(
            admin,
            UserCreateBuilder::default()
                .name(format!("fix-system-usr-{unique}"))
                .domain_id(domain_id)
                .password(FIXTURE_PASSWORD)
                .enabled(true)
                .build()?,
        )
        .await?;
        let session_result = async {
            let role = list_roles(admin)
                .await?
                .into_iter()
                .find(|role| role.name == role_name)
                .ok_or_eyre(format!("bootstrap `{role_name}` role must exist"))?;
            add_system_grant(admin, &user.id, &role.id).await?;

            let scope = Scope::System(ScopeSystem { all: Some(true) });
            get_user_session(&user.name, FIXTURE_PASSWORD, domain_id, Some(&scope)).await
        }
        .await;

        match session_result {
            Ok(session) => Ok(Self { session, user }),
            Err(error) => {
                warn_on_cleanup_failure("fixture user", user.delete().await);
                Err(error)
            }
        }
    }

    /// Delete the fixture user; its system role grant is removed implicitly.
    pub async fn cleanup(self) -> Result<()> {
        self.user.delete().await?;
        Ok(())
    }
}
