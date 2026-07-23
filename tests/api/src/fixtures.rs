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

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, ScopeProjectBuilder};
use openstack_keystone_api_types::v3::project::{Project, ProjectCreateBuilder};
use openstack_keystone_api_types::v3::user::{User, UserCreateBuilder};
use openstack_sdk::AsyncOpenStack;

use crate::assignment::grant::add_project_grant;
use crate::common::get_user_session;
use crate::guard::{AsyncResourceGuard, ResourceGuard};
use crate::identity::user::create_user;
use crate::resource::project::create_project;
use crate::role::list_roles;

/// Password used for all fixture users.
pub const FIXTURE_PASSWORD: &str = "fixture-user-password";

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
        let project = create_project(
            admin,
            ProjectCreateBuilder::default()
                .name(format!("fix-proj-{unique}"))
                .domain_id(domain_id)
                .build()?,
        )
        .await?;
        let user = create_user(
            admin,
            UserCreateBuilder::default()
                .name(format!("fix-usr-{unique}"))
                .domain_id(domain_id)
                .password(FIXTURE_PASSWORD)
                .enabled(true)
                .build()?,
        )
        .await?;
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
        let session =
            get_user_session(&user.name, FIXTURE_PASSWORD, domain_id, Some(&scope)).await?;
        Ok(Self {
            session,
            user,
            project,
        })
    }

    /// Delete the fixture user and project with the admin session that
    /// created them.
    pub async fn cleanup(self) -> Result<()> {
        self.user.delete().await?;
        self.project.delete().await?;
        Ok(())
    }
}
