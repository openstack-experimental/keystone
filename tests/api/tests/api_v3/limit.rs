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
//! v3 limits and the enforcement model authorization matrix and behavior.
//!
//! | endpoint                       | 2xx admin | 403 policy | 401 invalid token |
//! |--------------------------------|-----------|------------|-------------------|
//! | POST   /v3/limits              | `test_limit_crud_admin` | `test_limit_write_forbidden_for_member` | `test_limit_unauthorized` |
//! | GET    /v3/limits[/{id}]       | `test_limit_crud_admin` | `test_limit_visibility_of_project_member` | `test_limit_unauthorized` |
//! | PATCH/DELETE /v3/limits/{id}   | `test_limit_crud_admin` | `test_limit_write_forbidden_for_member` | `test_limit_unauthorized` |
//! | GET    /v3/limits/model        | `test_limit_model` | -  | `test_limit_unauthorized` |

use std::sync::Arc;

use eyre::{OptionExt, Result};
use http::StatusCode;
use secrecy::ExposeSecret;
use uuid::Uuid;

use openstack_keystone_api_types::v3::domain::{Domain, DomainCreateBuilder};
use openstack_keystone_api_types::v3::limit::*;
use openstack_keystone_api_types::v3::project::{Project, ProjectCreateBuilder};
use openstack_keystone_api_types::v3::registered_limit::*;
use openstack_keystone_api_types::v3::service::{Service, ServiceCreateBuilder};
use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{assert_forbidden, assert_status, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::ProjectScopedUser;
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::limit::*;
use test_api::resource::domain::create_domain;
use test_api::resource::get_system_scope_config;
use test_api::resource::project::create_project;
use test_api::service::create_service;

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&get_system_scope_config()?).await?,
    ))
}

/// Domain, service and registered limit `cores` the limits refer to.
struct World {
    admin: Arc<AsyncOpenStack>,
    domain: AsyncResourceGuard<Domain>,
    service: AsyncResourceGuard<Service>,
    registered: AsyncResourceGuard<RegisteredLimit>,
}

impl World {
    async fn new() -> Result<Self> {
        let admin = admin_session().await?;
        let domain = create_domain(
            &admin,
            DomainCreateBuilder::default()
                .name(format!("lim-dom-{}", Uuid::new_v4().simple()))
                .enabled(true)
                .build()?,
        )
        .await?;
        let service = create_service(
            &admin,
            ServiceCreateBuilder::default()
                .r#type("compute-limits")
                .name(format!("svc-{}", Uuid::new_v4().simple()))
                .enabled(true)
                .build()?,
        )
        .await?;
        let registered = create_registered_limits(
            &admin,
            vec![
                RegisteredLimitCreateBuilder::default()
                    .service_id(service.id.clone())
                    .resource_name("cores")
                    .default_limit(10)
                    .build()?,
            ],
        )
        .await?
        .pop()
        .expect("one registered limit created");
        Ok(Self {
            admin,
            domain,
            service,
            registered,
        })
    }

    async fn project(&self) -> Result<AsyncResourceGuard<Project>> {
        create_project(
            &self.admin,
            ProjectCreateBuilder::default()
                .name(format!("lim-prj-{}", Uuid::new_v4().simple()))
                .domain_id(self.domain.id.clone())
                .build()?,
        )
        .await
    }

    fn project_limit(&self, project_id: &str, value: i32) -> Result<LimitCreate> {
        Ok(LimitCreateBuilder::default()
            .service_id(self.service.id.clone())
            .resource_name("cores")
            .resource_limit(value)
            .project_id(project_id)
            .build()?)
    }

    async fn cleanup(self) -> Result<()> {
        self.registered.delete().await?;
        self.service.delete().await?;
        self.domain.delete().await?;
        Ok(())
    }
}

#[tokio::test]
async fn test_limit_crud_admin() -> Result<()> {
    let world = World::new().await?;
    let project = world.project().await?;

    // Project limit.
    let mut data = world.project_limit(&project.id, 5)?;
    data.description = Some("descr".into());
    let limit = create_limits(&world.admin, vec![data])
        .await?
        .pop()
        .expect("one limit created");
    assert_eq!(Some(project.id.clone()), limit.project_id);
    assert_eq!(None, limit.domain_id);
    assert_eq!(5, limit.resource_limit);
    assert_eq!("cores", limit.resource_name);
    assert_eq!(world.service.id, limit.service_id);
    assert_eq!(Some("descr".to_string()), limit.description);

    // Domain limit.
    let domain_limit = create_limits(
        &world.admin,
        vec![
            LimitCreateBuilder::default()
                .service_id(world.service.id.clone())
                .resource_name("cores")
                .resource_limit(100)
                .domain_id(world.domain.id.clone())
                .build()?,
        ],
    )
    .await?
    .pop()
    .expect("one limit created");
    assert_eq!(Some(world.domain.id.clone()), domain_limit.domain_id);
    assert_eq!(None, domain_limit.project_id);

    // Show.
    assert_eq!(*limit, show_limit(&world.admin, &limit.id).await?);

    // List with filters.
    let by_project = list_limits(&world.admin, &[("project_id", &project.id)]).await?;
    assert_eq!(1, by_project.len());
    assert_eq!(limit.id, by_project[0].id);
    let by_domain = list_limits(&world.admin, &[("domain_id", &world.domain.id)]).await?;
    assert_eq!(1, by_domain.len());
    assert_eq!(domain_limit.id, by_domain[0].id);
    let by_service = list_limits(&world.admin, &[("service_id", &world.service.id)]).await?;
    assert_eq!(2, by_service.len());
    assert!(
        list_limits(&world.admin, &[("resource_name", "unknown-resource")])
            .await?
            .is_empty()
    );

    // Update: zero is a valid value, the description can be reset.
    let updated = update_limit(
        &world.admin,
        &limit.id,
        LimitUpdateBuilder::default()
            .resource_limit(0)
            .description(None)
            .build()?,
    )
    .await?;
    assert_eq!(0, updated.resource_limit);
    assert_eq!(None, updated.description);

    // Delete.
    let limit_id = limit.id.clone();
    limit.delete().await?;
    assert_status(
        show_limit(&world.admin, &limit_id).await,
        StatusCode::NOT_FOUND,
        "deleted limit must be gone",
    );
    domain_limit.delete().await?;
    project.delete().await?;
    world.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_limit_batch_create() -> Result<()> {
    let world = World::new().await?;
    let project1 = world.project().await?;
    let project2 = world.project().await?;

    let created = create_limits(
        &world.admin,
        vec![
            world.project_limit(&project1.id, 1)?,
            world.project_limit(&project2.id, 2)?,
        ],
    )
    .await?;
    assert_eq!(2, created.len());

    for guard in created {
        guard.delete().await?;
    }
    project1.delete().await?;
    project2.delete().await?;
    world.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_limit_validation_and_conflicts() -> Result<()> {
    let world = World::new().await?;
    let project = world.project().await?;

    // Both project and domain.
    let mut both = world.project_limit(&project.id, 1)?;
    both.domain_id = Some(world.domain.id.clone());
    assert_status(
        create_limits(&world.admin, vec![both]).await,
        StatusCode::BAD_REQUEST,
        "project and domain together",
    );
    // Neither.
    let mut neither = world.project_limit(&project.id, 1)?;
    neither.project_id = None;
    assert_status(
        create_limits(&world.admin, vec![neither]).await,
        StatusCode::BAD_REQUEST,
        "neither project nor domain",
    );
    // Unknown project.
    assert_status(
        create_limits(
            &world.admin,
            vec![world.project_limit(&Uuid::new_v4().simple().to_string(), 1)?],
        )
        .await,
        StatusCode::BAD_REQUEST,
        "unknown project",
    );
    // No registered limit for the resource.
    let mut unregistered = world.project_limit(&project.id, 1)?;
    unregistered.resource_name = "unregistered".into();
    assert_forbidden(
        create_limits(&world.admin, vec![unregistered]).await,
        "no registered limit",
    );
    // Duplicate.
    let first = create_limits(&world.admin, vec![world.project_limit(&project.id, 1)?]).await?;
    assert_status(
        create_limits(&world.admin, vec![world.project_limit(&project.id, 2)?]).await,
        StatusCode::CONFLICT,
        "duplicate limit",
    );
    // The registered limit referenced by a limit is protected.
    assert_forbidden(
        delete_registered_limit(&world.admin, &world.registered.id).await,
        "referenced registered limit must not be deleted",
    );
    assert_forbidden(
        update_registered_limit(
            &world.admin,
            &world.registered.id,
            RegisteredLimitUpdateBuilder::default()
                .default_limit(1)
                .build()?,
        )
        .await,
        "referenced registered limit must not be updated",
    );
    // Only the value and the description can be changed.
    let token = world
        .admin
        .get_auth_token()
        .ok_or_eyre("admin session has a token")?;
    let rsp = raw_request(
        http::Method::PATCH,
        &format!("v3/limits/{}", first[0].id),
        Some(token.expose_secret()),
        Some(serde_json::json!({"limit": {"project_id": "other"}})),
    )
    .await?;
    assert_eq!(StatusCode::BAD_REQUEST, rsp.status());

    for guard in first {
        guard.delete().await?;
    }
    project.delete().await?;
    world.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_limit_model() -> Result<()> {
    let admin = admin_session().await?;
    let model = get_limit_model(&admin).await?;
    assert!(
        model.name == "flat" || model.name == "strict_two_level",
        "unexpected model {}",
        model.name
    );
    assert!(!model.description.is_empty());
    Ok(())
}

/// A project scoped member sees the limits of its own project only.
#[tokio::test]
async fn test_limit_visibility_of_project_member() -> Result<()> {
    let world = World::new().await?;
    let member = ProjectScopedUser::provision(&world.admin, &world.domain.id, "member").await?;
    let other = world.project().await?;
    let own_limit = create_limits(
        &world.admin,
        vec![world.project_limit(&member.project.id, 1)?],
    )
    .await?;
    let other_limit = create_limits(&world.admin, vec![world.project_limit(&other.id, 2)?]).await?;

    // Own limit.
    let shown = show_limit(&member.session, &own_limit[0].id).await?;
    assert_eq!(own_limit[0].id, shown.id);
    // Foreign limit.
    assert_forbidden(
        show_limit(&member.session, &other_limit[0].id).await,
        "member must not see the limit of another project",
    );
    // The list only contains the own limit.
    let listed = list_limits(&member.session, &[("service_id", &world.service.id)]).await?;
    assert_eq!(1, listed.len());
    assert_eq!(own_limit[0].id, listed[0].id);
    // The enforcement model is readable.
    get_limit_model(&member.session).await?;

    for guard in own_limit.into_iter().chain(other_limit) {
        guard.delete().await?;
    }
    other.delete().await?;
    member.cleanup().await?;
    world.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_limit_write_forbidden_for_member() -> Result<()> {
    let world = World::new().await?;
    let member = ProjectScopedUser::provision(&world.admin, &world.domain.id, "member").await?;
    let limit = create_limits(
        &world.admin,
        vec![world.project_limit(&member.project.id, 1)?],
    )
    .await?;

    assert_forbidden(
        create_limits(
            &member.session,
            vec![world.project_limit(&member.project.id, 2)?],
        )
        .await,
        "member must not create limits",
    );
    assert_forbidden(
        update_limit(
            &member.session,
            &limit[0].id,
            LimitUpdateBuilder::default().resource_limit(5).build()?,
        )
        .await,
        "member must not update limits",
    );
    assert_forbidden(
        delete_limit(&member.session, &limit[0].id).await,
        "member must not delete limits",
    );

    for guard in limit {
        guard.delete().await?;
    }
    member.cleanup().await?;
    world.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_limit_unauthorized() -> Result<()> {
    for (method, path, body) in [
        (http::Method::GET, "v3/limits", None),
        (http::Method::GET, "v3/limits/some-id", None),
        (http::Method::GET, "v3/limits/model", None),
        (
            http::Method::POST,
            "v3/limits",
            Some(serde_json::json!({"limits": [
                {"service_id": "s", "resource_name": "cores", "resource_limit": 1, "project_id": "p"}
            ]})),
        ),
        (
            http::Method::PATCH,
            "v3/limits/some-id",
            Some(serde_json::json!({"limit": {"resource_limit": 1}})),
        ),
        (http::Method::DELETE, "v3/limits/some-id", None),
    ] {
        let rsp = raw_request(method, path, Some("invalid-token"), body).await?;
        assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    }
    Ok(())
}
