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
//! Domain authorization matrix for issue #994.

use eyre::{OptionExt, Result};
use uuid::Uuid;

use openstack_keystone_api_types::v3::domain::{DomainCreateBuilder, DomainUpdateBuilder};

use test_api::asserts::{
    RawUnauthorizedRequest, assert_forbidden, assert_raw_request_unauthorized_with_cleanup,
    assert_raw_requests_unauthorized, assert_unauthorized,
};
use test_api::common::get_system_scope_session;
use test_api::fixtures::{ProjectScopedUser, revoked_admin_client, warn_on_cleanup_failure};
use test_api::guard::ResourceGuard;
use test_api::resource::domain::{
    DomainListRequest, create_domain, delete_domain, get_domain, list_domains, update_domain,
};

fn domain_create() -> Result<openstack_keystone_api_types::v3::domain::DomainCreate> {
    Ok(DomainCreateBuilder::default()
        .name(format!("domain-authz-{}", Uuid::new_v4().simple()))
        .enabled(true)
        .build()?)
}

fn domain_non_create_unauthorized_requests() -> [RawUnauthorizedRequest<'static>; 4] {
    [
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/domains/default",
            body: None,
            message: "unauthenticated requests must not show domains",
        },
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/domains",
            body: None,
            message: "unauthenticated requests must not list domains",
        },
        RawUnauthorizedRequest {
            method: http::Method::PATCH,
            path: "v3/domains/missing-domain",
            body: Some(serde_json::json!({"domain": {"enabled": false}})),
            message: "unauthenticated requests must not update domains",
        },
        RawUnauthorizedRequest {
            method: http::Method::DELETE,
            path: "v3/domains/missing-domain",
            body: None,
            message: "unauthenticated requests must not delete domains",
        },
    ]
}

async fn assert_domain_requests_unauthorized(token: Option<&str>) -> Result<()> {
    assert_domain_create_unauthorized(token).await?;
    assert_raw_requests_unauthorized(domain_non_create_unauthorized_requests(), token).await
}

async fn assert_domain_create_unauthorized(token: Option<&str>) -> Result<()> {
    let admin = get_system_scope_session().await?;
    let domain_id = format!("domain-authz-{}", Uuid::new_v4().simple());
    let cleanup_domain_id = domain_id.clone();
    let admin_for_cleanup = admin.clone();
    assert_raw_request_unauthorized_with_cleanup(
        RawUnauthorizedRequest {
            method: http::Method::POST,
            path: "v3/domains",
            body: Some(serde_json::json!({
                "domain": {
                    "id": domain_id,
                    "name": format!("domain-authz-{}", Uuid::new_v4().simple()),
                    "enabled": true
                }
            })),
            message: "unauthenticated requests must not create domains",
        },
        token,
        move |_| async move { delete_domain(&admin_for_cleanup, &cleanup_domain_id).await },
    )
    .await
}

async fn assert_domain_non_create_unauthorized(index: usize, token: Option<&str>) -> Result<()> {
    let request = domain_non_create_unauthorized_requests()
        .into_iter()
        .nth(index)
        .ok_or_eyre("domain authorization request must exist")?;
    test_api::asserts::assert_raw_request_unauthorized(request, token).await
}

#[tokio::test]
async fn test_domain_create_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = match create_domain(&member.session, domain_create()?).await {
        Ok(domain) => {
            delete_domain(&admin, &domain.id).await?;
            warn_on_cleanup_failure("unexpected domain guard", domain.delete().await);
            Ok(())
        }
        Err(error) => Err(error),
    };

    member.cleanup().await?;
    assert_forbidden(result, "a project-scoped member must not create domains");
    Ok(())
}

#[tokio::test]
async fn test_domain_list_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = list_domains(&member.session, DomainListRequest::default())
        .await
        .map(|_| ());

    member.cleanup().await?;
    assert_forbidden(result, "a project-scoped member must not list domains");
    Ok(())
}

#[tokio::test]
async fn test_domain_update_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let domain = create_domain(&admin, domain_create()?).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = update_domain(
        &member.session,
        &domain.id,
        DomainUpdateBuilder::default()
            .name(format!("forbidden-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await
    .map(|_| ());

    member.cleanup().await?;
    domain.delete().await?;
    assert_forbidden(result, "a project-scoped member must not update domains");
    Ok(())
}

#[tokio::test]
async fn test_domain_delete_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let domain = create_domain(&admin, domain_create()?).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = delete_domain(&member.session, &domain.id).await;

    member.cleanup().await?;
    if result.is_ok() {
        warn_on_cleanup_failure(
            "domain deleted by unauthorized caller",
            domain.delete().await,
        );
    } else {
        domain.delete().await?;
    }
    assert_forbidden(result, "a project-scoped member must not delete domains");
    Ok(())
}

#[tokio::test]
async fn test_domain_show_allows_project_member_own_domain() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let shown_id = get_domain(&member.session, "default")
        .await?
        .ok_or_eyre("default domain must exist")?
        .id;

    member.cleanup().await?;
    assert_eq!(shown_id, "default");
    Ok(())
}

#[tokio::test]
async fn test_domain_show_forbidden_project_member_other_domain() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let domain = create_domain(&admin, domain_create()?).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = get_domain(&member.session, &domain.id).await.map(|_| ());

    member.cleanup().await?;
    domain.delete().await?;
    assert_forbidden(
        result,
        "a project-scoped member must not show another project domain",
    );
    Ok(())
}

#[tokio::test]
async fn test_domain_create_rejects_invalid_token() -> Result<()> {
    assert_domain_create_unauthorized(Some("invalid-token")).await
}

#[tokio::test]
async fn test_domain_show_rejects_invalid_token() -> Result<()> {
    assert_domain_non_create_unauthorized(0, Some("invalid-token")).await
}

#[tokio::test]
async fn test_domain_list_rejects_invalid_token() -> Result<()> {
    assert_domain_non_create_unauthorized(1, Some("invalid-token")).await
}

#[tokio::test]
async fn test_domain_update_rejects_invalid_token() -> Result<()> {
    assert_domain_non_create_unauthorized(2, Some("invalid-token")).await
}

#[tokio::test]
async fn test_domain_delete_rejects_invalid_token() -> Result<()> {
    assert_domain_non_create_unauthorized(3, Some("invalid-token")).await
}

#[tokio::test]
async fn test_domain_requests_reject_missing_token() -> Result<()> {
    assert_domain_requests_unauthorized(None).await
}

#[tokio::test]
async fn test_domain_create_rejects_revoked_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let caller = revoked_admin_client().await?;
    let domain_id = format!("domain-authz-revoked-{}", Uuid::new_v4().simple());
    let response = caller
        .client
        .post(caller.base_url.join("v3/domains")?)
        .json(&serde_json::json!({
            "domain": {
                "id": domain_id,
                "name": format!("domain-authz-revoked-{}", Uuid::new_v4().simple()),
                "enabled": true
            }
        }))
        .send()
        .await?;
    let result = response.error_for_status().map(|_| ());

    if result.is_ok() {
        delete_domain(&admin, &domain_id).await?;
    }
    assert_unauthorized(
        result,
        "a revoked token must not create a domain even when its original scope was authorized",
    );
    Ok(())
}
