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
//! Credential ownership and authorization matrix for issue #994.

use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::credential::{
    CredentialCreate, CredentialCreateBuilder, CredentialResponse, CredentialUpdateBuilder,
};
use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{
    RawUnauthorizedRequest, assert_forbidden, assert_raw_request_unauthorized_with_cleanup,
    assert_raw_requests_unauthorized, assert_unauthorized,
};
use test_api::common::get_system_scope_session;
use test_api::credential::{
    create_credential, delete_credential, list_credentials, show_credential, update_credential,
};
use test_api::fixtures::{
    ProjectScopedUser, cleanup_project_scoped_users, provision_fixture_pair, revoked_admin_client,
    warn_on_cleanup_failure,
};
use test_api::guard::ResourceGuard;

async fn two_members(
    admin: &Arc<AsyncOpenStack>,
) -> Result<(ProjectScopedUser, ProjectScopedUser)> {
    let first = ProjectScopedUser::provision(admin, "default", "member").await?;
    provision_fixture_pair(
        first,
        ProjectScopedUser::provision(admin, "default", "member"),
        |first| first.cleanup(),
        "first member fixture",
    )
    .await
}

fn credential_create(user_id: Option<&str>, marker_type: &str) -> Result<CredentialCreate> {
    let mut builder = CredentialCreateBuilder::default();
    builder
        .blob(format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple()))
        .r#type(marker_type);
    if let Some(user_id) = user_id {
        builder.user_id(user_id);
    }
    Ok(builder.build()?)
}

fn credential_non_create_unauthorized_requests() -> [RawUnauthorizedRequest<'static>; 4] {
    [
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/credentials/missing-credential",
            body: None,
            message: "unauthenticated requests must not show credentials",
        },
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/credentials",
            body: None,
            message: "unauthenticated requests must not list credentials",
        },
        RawUnauthorizedRequest {
            method: http::Method::PATCH,
            path: "v3/credentials/missing-credential",
            body: Some(serde_json::json!({
                "credential": {"type": "credential-authz"}
            })),
            message: "unauthenticated requests must not update credentials",
        },
        RawUnauthorizedRequest {
            method: http::Method::DELETE,
            path: "v3/credentials/missing-credential",
            body: None,
            message: "unauthenticated requests must not delete credentials",
        },
    ]
}

async fn assert_credential_requests_unauthorized(token: Option<&str>) -> Result<()> {
    let admin = get_system_scope_session().await?;
    let admin_for_cleanup = admin.clone();
    let owner = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let owner_id = owner.user.id.clone();
    let result = assert_raw_request_unauthorized_with_cleanup(
        RawUnauthorizedRequest {
            method: http::Method::POST,
            path: "v3/credentials",
            body: Some(serde_json::json!({
                "credential": {
                    "blob": format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple()),
                    "type": format!("credential-authz-{}", Uuid::new_v4().simple()),
                    "user_id": owner_id
                }
            })),
            message: "unauthenticated requests must not create credentials",
        },
        token,
        move |response| async move {
            let created: CredentialResponse = response.json().await?;
            delete_credential(&admin_for_cleanup, &created.credential.id).await
        },
    )
    .await;

    owner.cleanup().await?;
    result?;
    assert_raw_requests_unauthorized(credential_non_create_unauthorized_requests(), token).await
}

#[tokio::test]
async fn test_credential_create_forbidden_other_user() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (caller, owner) = two_members(&admin).await?;
    let marker_type = format!("credential-authz-{}", Uuid::new_v4().simple());
    let result = match create_credential(
        &caller.session,
        credential_create(Some(&owner.user.id), &marker_type)?,
    )
    .await
    {
        Ok(credential) => {
            delete_credential(&admin, &credential.id).await?;
            warn_on_cleanup_failure("unexpected credential guard", credential.delete().await);
            Ok(())
        }
        Err(error) => Err(error),
    };

    cleanup_project_scoped_users([caller, owner]).await?;
    assert_forbidden(
        result,
        "a member must not create credentials for another user",
    );
    Ok(())
}

#[tokio::test]
async fn test_credential_show_forbidden_other_user() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (caller, owner) = two_members(&admin).await?;
    let marker_type = format!("credential-authz-{}", Uuid::new_v4().simple());
    let credential = create_credential(
        &admin,
        credential_create(Some(&owner.user.id), &marker_type)?,
    )
    .await?;
    let result = show_credential(&caller.session, &credential.id)
        .await
        .map(|shown| shown.id);

    credential.delete().await?;
    cleanup_project_scoped_users([caller, owner]).await?;
    assert_forbidden(result, "a member must not show another user's credential");
    Ok(())
}

#[tokio::test]
async fn test_credential_list_filters_other_user() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (caller, owner) = two_members(&admin).await?;
    let marker_type = format!("credential-authz-{}", Uuid::new_v4().simple());
    let own = create_credential(
        &caller.session,
        credential_create(Some(&caller.user.id), &marker_type)?,
    )
    .await?;
    let other = create_credential(
        &admin,
        credential_create(Some(&owner.user.id), &marker_type)?,
    )
    .await?;
    let own_id = own.id.clone();
    let other_id = other.id.clone();

    let visible_ids = list_credentials(&caller.session, Some(&marker_type), Some(&caller.user.id))
        .await
        .map(|credentials| {
            credentials
                .into_iter()
                .map(|credential| credential.id)
                .collect::<Vec<_>>()
        });

    own.delete().await?;
    other.delete().await?;
    cleanup_project_scoped_users([caller, owner]).await?;
    let visible_ids = visible_ids?;
    assert!(
        visible_ids.contains(&own_id),
        "a member must see their own credential"
    );
    assert!(
        !visible_ids.contains(&other_id),
        "per-item show policy must filter another user's credential"
    );
    Ok(())
}

#[tokio::test]
async fn test_credential_update_forbidden_other_user() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (caller, owner) = two_members(&admin).await?;
    let marker_type = format!("credential-authz-{}", Uuid::new_v4().simple());
    let credential = create_credential(
        &admin,
        credential_create(Some(&owner.user.id), &marker_type)?,
    )
    .await?;
    let result = update_credential(
        &caller.session,
        &credential.id,
        CredentialUpdateBuilder::default()
            .r#type(format!("forbidden-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await
    .map(|updated| updated.id);

    credential.delete().await?;
    cleanup_project_scoped_users([caller, owner]).await?;
    assert_forbidden(result, "a member must not update another user's credential");
    Ok(())
}

#[tokio::test]
async fn test_credential_delete_forbidden_other_user() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (caller, owner) = two_members(&admin).await?;
    let marker_type = format!("credential-authz-{}", Uuid::new_v4().simple());
    let credential = create_credential(
        &admin,
        credential_create(Some(&owner.user.id), &marker_type)?,
    )
    .await?;
    let result = delete_credential(&caller.session, &credential.id).await;

    if result.is_ok() {
        warn_on_cleanup_failure(
            "credential deleted by unauthorized caller",
            credential.delete().await,
        );
    } else {
        credential.delete().await?;
    }
    cleanup_project_scoped_users([caller, owner]).await?;
    assert_forbidden(result, "a member must not delete another user's credential");
    Ok(())
}

#[tokio::test]
async fn test_credential_requests_reject_invalid_token() -> Result<()> {
    assert_credential_requests_unauthorized(Some("invalid-token")).await
}

#[tokio::test]
async fn test_credential_requests_reject_missing_token() -> Result<()> {
    assert_credential_requests_unauthorized(None).await
}

#[tokio::test]
async fn test_credential_create_rejects_revoked_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let caller = revoked_admin_client().await?;
    let owner = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result: Result<()> = async {
        let response = caller
            .client
            .post(caller.base_url.join("v3/credentials")?)
            .json(&serde_json::json!({
                "credential": {
                    "blob": format!(
                        r#"{{"seed":"{}"}}"#,
                        Uuid::new_v4().simple()
                    ),
                    "type": format!(
                        "credential-authz-revoked-{}",
                        Uuid::new_v4().simple()
                    ),
                    "user_id": owner.user.id
                }
            }))
            .send()
            .await?;
        match response.error_for_status() {
            Ok(response) => {
                let created: CredentialResponse = response.json().await?;
                delete_credential(&admin, &created.credential.id).await?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
    .await;

    owner.cleanup().await?;
    assert_unauthorized(result, "a revoked token must not create a credential");
    Ok(())
}
