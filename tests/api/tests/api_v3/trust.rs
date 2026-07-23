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

mod create;
mod delete;
mod list;
mod show;

use std::sync::Arc;

use eyre::{OptionExt, Result};
use uuid::Uuid;

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, ScopeProjectBuilder};
use openstack_keystone_api_types::v3::project::{Project, ProjectCreateBuilder};
use openstack_keystone_api_types::v3::user::{User, UserCreateBuilder};
use openstack_sdk::AsyncOpenStack;

use test_api::assignment::grant::add_project_grant;
use test_api::common::get_user_session;
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::identity::user::create_user;
use test_api::resource::project::create_project;
use test_api::role::list_roles;

pub(crate) const TRUST_FIXTURE_PASSWORD: &str = "trust-fixture-password";

/// A trustor user holding the `member` role on a project, authenticated
/// through the live password-auth path.
///
/// `identity/trust/create` requires the caller to self-issue (be its own
/// `trustor_user_id`) and to carry `member` in its token's role set --
/// there is no admin bypass, matching python keystone's
/// `identity:create_trust` -- so trust-creation tests must act through this
/// session rather than the admin `tc`. All fixture resources are created
/// by, and cleaned up with, the admin session.
pub(crate) struct TrustorSession {
    pub session: Arc<AsyncOpenStack>,
    pub user: AsyncResourceGuard<User>,
    pub project: AsyncResourceGuard<Project>,
}

impl TrustorSession {
    pub(crate) async fn provision(admin: &Arc<AsyncOpenStack>, domain_id: &str) -> Result<Self> {
        let unique = Uuid::new_v4().simple().to_string();
        let project = create_project(
            admin,
            ProjectCreateBuilder::default()
                .name(format!("trust-proj-{unique}"))
                .domain_id(domain_id)
                .parent_id(domain_id)
                .is_domain(false)
                .enabled(true)
                .build()?,
        )
        .await?;
        let user = create_user(
            admin,
            UserCreateBuilder::default()
                .name(format!("trustor-{unique}"))
                .domain_id(domain_id)
                .password(TRUST_FIXTURE_PASSWORD)
                .enabled(true)
                .build()?,
        )
        .await?;
        let member_role = list_roles(admin)
            .await?
            .into_iter()
            .find(|role| role.name == "member")
            .ok_or_eyre("bootstrap `member` role must exist")?;
        add_project_grant(admin, &project.id, &user.id, &member_role.id).await?;

        let scope = Scope::Project(
            ScopeProjectBuilder::default()
                .id(project.id.clone())
                .domain(DomainBuilder::default().id(domain_id).build()?)
                .build()?,
        );
        let session =
            get_user_session(&user.name, TRUST_FIXTURE_PASSWORD, domain_id, Some(&scope)).await?;
        Ok(Self {
            session,
            user,
            project,
        })
    }

    pub(crate) async fn cleanup(self) -> Result<()> {
        self.user.delete().await?;
        self.project.delete().await?;
        Ok(())
    }
}
