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

use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::role::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::assert_forbidden;
use test_api::common::raw_request;
use test_api::fixtures::{ProjectScopedUser, SystemScopedUser};
use test_api::role::imply::*;
use test_api::role::{create_role, delete_role};

#[tokio::test]
#[traced_test]
async fn test_list_role_inferences() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let prior_name = format!("prior_{}", Uuid::new_v4().simple());
    let implied_name = format!("implied_{}", Uuid::new_v4().simple());

    let prior_role =
        create_role(&tc, RoleCreateBuilder::default().name(prior_name).build()?).await?;
    let implied_role = create_role(
        &tc,
        RoleCreateBuilder::default().name(implied_name).build()?,
    )
    .await?;

    create_implied_role(&tc, &prior_role.id, &implied_role.id).await?;

    let inferences = list_role_inferences(&tc).await?;

    let found = inferences.iter().any(|r| {
        r.prior_role.id == prior_role.id
            && r.implies.iter().any(|imply| imply.id == implied_role.id)
    });
    assert!(found, "created inference should be in the global list");

    delete_implied_role(&tc, &prior_role.id, &implied_role.id).await?;
    delete_role(&tc, &implied_role.id).await?;
    delete_role(&tc, &prior_role.id).await?;
    Ok(())
}

/// `policy/role/imply_rule/list.rego` allows only `admin` (or a
/// system-scoped `reader`); a project-scoped member must be denied.
#[tokio::test]
async fn test_list_role_inferences_forbidden_project_scoped_member() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;

    assert_forbidden(
        list_role_inferences(&member.session).await,
        "a project-scoped member must not list global role inferences",
    );

    member.cleanup().await?;
    Ok(())
}

/// Exercise the policy's non-admin positive branch: a reader is permitted only
/// when the token is scoped to `system: all`.
#[tokio::test]
async fn test_list_role_inferences_allowed_system_scoped_reader() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let reader = SystemScopedUser::provision(&admin, "default", "reader").await?;

    let list_result = list_role_inferences(&reader.session).await;
    let cleanup_result = reader.cleanup().await;

    list_result?;
    cleanup_result?;
    Ok(())
}

#[tokio::test]
async fn test_list_role_inferences_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v3/role_inferences",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}
