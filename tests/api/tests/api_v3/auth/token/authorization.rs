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
//! Token show and revoke authorization matrix for issue #994.

use eyre::{OptionExt, Result};
use secrecy::SecretString;

use openstack_keystone_api_types::scope::{
    DomainBuilder, Scope, ScopeProjectBuilder, System as ScopeSystem,
};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::auth::token::{
    check_token, check_token_with_auth, revoke_token, revoke_token_with_auth,
};
use test_api::common::get_system_scope_session;
use test_api::common::{TestClient, get_password_auth};
use test_api::fixtures::{
    FIXTURE_PASSWORD, ProjectScopedUser, SystemScopedUser, cleanup_project_scoped_users,
    provision_fixture_pair,
};

async fn project_client(fixture: &ProjectScopedUser) -> Result<TestClient> {
    let mut client = TestClient::default()?;
    client
        .auth_password(
            get_password_auth(&fixture.user.name, FIXTURE_PASSWORD, "default")?,
            Some(Scope::Project(
                ScopeProjectBuilder::default()
                    .id(fixture.project.id.clone())
                    .domain(DomainBuilder::default().id("default").build()?)
                    .build()?,
            )),
        )
        .await?;
    Ok(client)
}

async fn system_client(fixture: &SystemScopedUser) -> Result<TestClient> {
    let mut client = TestClient::default()?;
    client
        .auth_password(
            get_password_auth(&fixture.user.name, FIXTURE_PASSWORD, "default")?,
            Some(Scope::System(ScopeSystem { all: Some(true) })),
        )
        .await?;
    Ok(client)
}

#[tokio::test]
async fn test_token_owner_can_show_and_revoke_own_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let owner = ProjectScopedUser::provision(&admin, "default", "member").await?;

    let result: Result<(reqwest::Response, reqwest::Response, reqwest::Response)> = async {
        let owner_client = project_client(&owner).await?;
        let mut admin_client = TestClient::default()?;
        admin_client.auth_admin_system().await?;
        let owner_token = owner_client
            .token
            .as_ref()
            .ok_or_eyre("the owner client must be authenticated")?;

        let show = check_token(&owner_client, owner_token).await?;
        let revoke = revoke_token(&owner_client, owner_token).await?;
        let revoked = check_token(&admin_client, owner_token).await?;
        Ok((show, revoke, revoked))
    }
    .await;

    owner.cleanup().await?;
    let (show, revoke, revoked) = result?;
    test_api::asserts::assert_response_status(
        &show,
        http::StatusCode::OK,
        "unexpected raw response status",
    );
    test_api::asserts::assert_response_status(
        &revoke,
        http::StatusCode::NO_CONTENT,
        "unexpected raw response status",
    );
    test_api::asserts::assert_response_status(
        &revoked,
        http::StatusCode::NOT_FOUND,
        "unexpected raw response status",
    );
    Ok(())
}

#[tokio::test]
async fn test_project_member_cannot_show_or_revoke_another_users_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let target = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let (target, caller) = provision_fixture_pair(
        target,
        ProjectScopedUser::provision(&admin, "default", "member"),
        |target| target.cleanup(),
        "token target fixture",
    )
    .await?;

    let result: Result<(reqwest::Response, reqwest::Response)> = async {
        let target_client = project_client(&target).await?;
        let caller_client = project_client(&caller).await?;
        let target_token = target_client
            .token
            .as_ref()
            .ok_or_eyre("the target client must be authenticated")?;

        Ok((
            check_token(&caller_client, target_token).await?,
            revoke_token(&caller_client, target_token).await?,
        ))
    }
    .await;

    cleanup_project_scoped_users([target, caller]).await?;
    let (show, revoke) = result?;
    assert_forbidden(
        show.error_for_status(),
        "a project member must not show another user's token",
    );
    assert_forbidden(
        revoke.error_for_status(),
        "a project member must not revoke another user's token",
    );
    Ok(())
}

#[tokio::test]
async fn test_system_reader_can_show_but_not_revoke_another_users_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let target = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let (target, reader) = provision_fixture_pair(
        target,
        SystemScopedUser::provision(&admin, "default", "reader"),
        |target| target.cleanup(),
        "token target fixture",
    )
    .await?;

    let result: Result<(reqwest::Response, reqwest::Response)> = async {
        let target_client = project_client(&target).await?;
        let reader_client = system_client(&reader).await?;
        let target_token = target_client
            .token
            .as_ref()
            .ok_or_eyre("the target client must be authenticated")?;

        Ok((
            check_token(&reader_client, target_token).await?,
            revoke_token(&reader_client, target_token).await?,
        ))
    }
    .await;

    let target_cleanup = target.cleanup().await;
    let reader_cleanup = reader.cleanup().await;
    target_cleanup?;
    reader_cleanup?;

    let (show, revoke) = result?;
    test_api::asserts::assert_response_status(
        &show,
        http::StatusCode::OK,
        "unexpected raw response status",
    );
    assert_forbidden(
        revoke.error_for_status(),
        "a system reader must not revoke another user's token",
    );
    Ok(())
}

#[tokio::test]
async fn test_token_show_and_revoke_require_valid_authentication() -> Result<()> {
    let client = TestClient::default()?;
    let invalid = SecretString::from("invalid-token");

    let invalid_show = check_token_with_auth(&client, Some(&invalid), &invalid).await?;
    let invalid_revoke = revoke_token_with_auth(&client, Some(&invalid), &invalid).await?;
    let missing_show = check_token_with_auth(&client, None, &invalid).await?;
    let missing_revoke = revoke_token_with_auth(&client, None, &invalid).await?;

    assert_unauthorized(
        invalid_show.error_for_status(),
        "an invalid token must not show tokens",
    );
    assert_unauthorized(
        invalid_revoke.error_for_status(),
        "an invalid token must not revoke tokens",
    );
    assert_unauthorized(
        missing_show.error_for_status(),
        "a missing token must not show tokens",
    );
    assert_unauthorized(
        missing_revoke.error_for_status(),
        "a missing token must not revoke tokens",
    );
    Ok(())
}
