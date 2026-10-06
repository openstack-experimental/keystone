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
//! v3 registered limits authorization matrix and behavior.
//!
//! | endpoint                          | 2xx admin | 403 policy                  | 401 invalid token |
//! |-----------------------------------|-----------|-----------------------------|-------------------|
//! | POST   /v3/registered_limits      | `test_registered_limit_crud_admin` | `test_registered_limit_write_forbidden_for_member` | `test_registered_limit_unauthorized` |
//! | GET    /v3/registered_limits[/{id}]| `test_registered_limit_crud_admin` | (readable by any scoped caller) | `test_registered_limit_unauthorized` |
//! | PATCH/DELETE /v3/registered_limits/{id} | `test_registered_limit_crud_admin` | `test_registered_limit_write_forbidden_for_member` | `test_registered_limit_unauthorized` |

use std::sync::Arc;

use eyre::Result;
use http::StatusCode;
use uuid::Uuid;

use openstack_keystone_api_types::v3::domain::DomainCreateBuilder;
use openstack_keystone_api_types::v3::region::RegionCreateBuilder;
use openstack_keystone_api_types::v3::registered_limit::*;
use openstack_keystone_api_types::v3::service::ServiceCreateBuilder;
use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{assert_forbidden, assert_status, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::ProjectScopedUser;
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::limit::*;
use test_api::region::create_region;
use test_api::resource::domain::create_domain;
use test_api::resource::get_system_scope_config;
use test_api::service::create_service;

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&get_system_scope_config()?).await?,
    ))
}

async fn fresh_service(
    admin: &Arc<AsyncOpenStack>,
) -> Result<AsyncResourceGuard<openstack_keystone_api_types::v3::service::Service>> {
    create_service(
        admin,
        ServiceCreateBuilder::default()
            .r#type("compute-limits")
            .name(format!("svc-{}", Uuid::new_v4().simple()))
            .enabled(true)
            .build()?,
    )
    .await
}

fn registered(service_id: &str, name: &str, default_limit: i32) -> Result<RegisteredLimitCreate> {
    Ok(RegisteredLimitCreateBuilder::default()
        .service_id(service_id)
        .resource_name(name)
        .default_limit(default_limit)
        .build()?)
}

#[tokio::test]
async fn test_registered_limit_crud_admin() -> Result<()> {
    let admin = admin_session().await?;
    let service = fresh_service(&admin).await?;

    // Batch creation.
    let mut created = create_registered_limits(
        &admin,
        vec![
            registered(&service.id, "cores", 10)?,
            RegisteredLimitCreateBuilder::default()
                .service_id(service.id.clone())
                .resource_name("ram")
                .default_limit(-1)
                .description("memory")
                .build()?,
        ],
    )
    .await?;
    assert_eq!(2, created.len());
    let ram = created.pop().expect("two created");
    let cores = created.pop().expect("two created");
    assert_eq!("cores", cores.resource_name);
    assert_eq!(10, cores.default_limit);
    assert_eq!(None, cores.region_id);
    assert_eq!(Some("memory".to_string()), ram.description);
    assert_eq!(-1, ram.default_limit);

    // Show.
    let shown = show_registered_limit(&admin, &cores.id).await?;
    assert_eq!(*cores, shown);

    // List with filters.
    let all = list_registered_limits(&admin, &[("service_id", &service.id)]).await?;
    assert_eq!(2, all.len());
    let filtered = list_registered_limits(
        &admin,
        &[("service_id", &service.id), ("resource_name", "ram")],
    )
    .await?;
    assert_eq!(1, filtered.len());
    assert_eq!(ram.id, filtered[0].id);

    // Update.
    let updated = update_registered_limit(
        &admin,
        &cores.id,
        RegisteredLimitUpdateBuilder::default()
            .default_limit(20)
            .build()?,
    )
    .await?;
    assert_eq!(20, updated.default_limit);
    assert_eq!("cores", updated.resource_name);

    // Delete.
    let cores_id = cores.id.clone();
    cores.delete().await?;
    assert_status(
        show_registered_limit(&admin, &cores_id).await,
        StatusCode::NOT_FOUND,
        "deleted registered limit must be gone",
    );
    ram.delete().await?;
    service.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_registered_limit_duplicate_conflict() -> Result<()> {
    let admin = admin_session().await?;
    let service = fresh_service(&admin).await?;
    let created =
        create_registered_limits(&admin, vec![registered(&service.id, "cores", 1)?]).await?;

    assert_status(
        create_registered_limits(&admin, vec![registered(&service.id, "cores", 2)?]).await,
        StatusCode::CONFLICT,
        "duplicate registered limit",
    );

    for guard in created {
        guard.delete().await?;
    }
    service.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_registered_limit_batch_is_atomic() -> Result<()> {
    let admin = admin_session().await?;
    let service = fresh_service(&admin).await?;

    assert_status(
        create_registered_limits(
            &admin,
            vec![
                registered(&service.id, "cores", 1)?,
                registered(&service.id, "cores", 2)?,
            ],
        )
        .await,
        StatusCode::CONFLICT,
        "duplicate within the batch",
    );
    assert!(
        list_registered_limits(&admin, &[("service_id", &service.id)])
            .await?
            .is_empty(),
        "no part of the failed batch may remain"
    );

    service.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_registered_limit_unknown_service() -> Result<()> {
    let admin = admin_session().await?;
    assert_status(
        create_registered_limits(
            &admin,
            vec![registered(
                &Uuid::new_v4().simple().to_string(),
                "cores",
                1,
            )?],
        )
        .await,
        StatusCode::BAD_REQUEST,
        "unknown service",
    );
    Ok(())
}

#[tokio::test]
async fn test_registered_limit_invalid_value() -> Result<()> {
    let admin = admin_session().await?;
    let service = fresh_service(&admin).await?;
    assert_status(
        create_registered_limits(&admin, vec![registered(&service.id, "cores", -2)?]).await,
        StatusCode::BAD_REQUEST,
        "limit below -1",
    );
    service.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_registered_limit_not_found() -> Result<()> {
    let admin = admin_session().await?;
    assert_status(
        show_registered_limit(&admin, "does-not-exist").await,
        StatusCode::NOT_FOUND,
        "unknown registered limit",
    );
    assert_status(
        delete_registered_limit(&admin, "does-not-exist").await,
        StatusCode::NOT_FOUND,
        "unknown registered limit",
    );
    Ok(())
}

#[tokio::test]
async fn test_registered_limit_region_and_update() -> Result<()> {
    let admin = admin_session().await?;
    let service = fresh_service(&admin).await?;
    let region = create_region(&admin, RegionCreateBuilder::default().build()?).await?;

    // The same resource globally and for a region is not a duplicate.
    let mut regional = registered(&service.id, "cores", 2)?;
    regional.region_id = Some(region.id.clone());
    let mut created =
        create_registered_limits(&admin, vec![registered(&service.id, "cores", 1)?, regional])
            .await?;
    let regional = created.pop().expect("two created");
    let global = created.pop().expect("two created");
    assert_eq!(Some(region.id.clone()), regional.region_id);
    assert_eq!(None, global.region_id);

    // Filter by region.
    let by_region = list_registered_limits(&admin, &[("region_id", &region.id)]).await?;
    assert_eq!(1, by_region.len());
    assert_eq!(regional.id, by_region[0].id);
    let by_service = list_registered_limits(&admin, &[("service_id", &service.id)]).await?;
    assert_eq!(2, by_service.len());

    // Dropping the region would duplicate the global registered limit.
    assert_status(
        update_registered_limit(
            &admin,
            &regional.id,
            RegisteredLimitUpdateBuilder::default()
                .region_id(None)
                .build()?,
        )
        .await,
        StatusCode::CONFLICT,
        "region reset collides with the global registered limit",
    );

    // The description is updated on its own and can be cleared.
    let updated = update_registered_limit(
        &admin,
        &global.id,
        RegisteredLimitUpdateBuilder::default()
            .description(Some("new".to_string()))
            .build()?,
    )
    .await?;
    assert_eq!(Some("new".to_string()), updated.description);
    assert_eq!(1, updated.default_limit);
    let cleared = update_registered_limit(
        &admin,
        &global.id,
        RegisteredLimitUpdateBuilder::default()
            .description(None)
            .build()?,
    )
    .await?;
    assert_eq!(None, cleared.description);

    // Unknown ID and invalid value.
    assert_status(
        update_registered_limit(
            &admin,
            "does-not-exist",
            RegisteredLimitUpdateBuilder::default()
                .default_limit(1)
                .build()?,
        )
        .await,
        StatusCode::NOT_FOUND,
        "unknown registered limit",
    );
    assert_status(
        update_registered_limit(
            &admin,
            &global.id,
            RegisteredLimitUpdateBuilder::default()
                .default_limit(-2)
                .build()?,
        )
        .await,
        StatusCode::BAD_REQUEST,
        "limit below -1",
    );

    regional.delete().await?;
    global.delete().await?;
    region.delete().await?;
    service.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_registered_limit_read_allowed_write_forbidden_for_member() -> Result<()> {
    let admin = admin_session().await?;
    let domain = create_domain(
        &admin,
        DomainCreateBuilder::default()
            .name(format!("rl-dom-{}", Uuid::new_v4().simple()))
            .enabled(true)
            .build()?,
    )
    .await?;
    let service = fresh_service(&admin).await?;
    let created =
        create_registered_limits(&admin, vec![registered(&service.id, "cores", 1)?]).await?;
    let member = ProjectScopedUser::provision(&admin, &domain.id, "member").await?;

    // Any scoped caller may read ...
    let shown = show_registered_limit(&member.session, &created[0].id).await?;
    assert_eq!(created[0].id, shown.id);
    let listed = list_registered_limits(&member.session, &[("service_id", &service.id)]).await?;
    assert_eq!(1, listed.len());

    // ... but only the admin may write.
    assert_forbidden(
        create_registered_limits(&member.session, vec![registered(&service.id, "ram", 1)?]).await,
        "member must not create registered limits",
    );
    assert_forbidden(
        update_registered_limit(
            &member.session,
            &created[0].id,
            RegisteredLimitUpdateBuilder::default()
                .default_limit(5)
                .build()?,
        )
        .await,
        "member must not update registered limits",
    );
    assert_forbidden(
        delete_registered_limit(&member.session, &created[0].id).await,
        "member must not delete registered limits",
    );

    member.cleanup().await?;
    for guard in created {
        guard.delete().await?;
    }
    service.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_registered_limit_unauthorized() -> Result<()> {
    for (method, path, body) in [
        (http::Method::GET, "v3/registered_limits", None),
        (http::Method::GET, "v3/registered_limits/some-id", None),
        (
            http::Method::POST,
            "v3/registered_limits",
            Some(serde_json::json!({"registered_limits": [
                {"service_id": "s", "resource_name": "cores", "default_limit": 1}
            ]})),
        ),
        (
            http::Method::PATCH,
            "v3/registered_limits/some-id",
            Some(serde_json::json!({"registered_limit": {"default_limit": 1}})),
        ),
        (http::Method::DELETE, "v3/registered_limits/some-id", None),
    ] {
        let rsp = raw_request(method, path, Some("invalid-token"), body).await?;
        assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    }
    Ok(())
}
