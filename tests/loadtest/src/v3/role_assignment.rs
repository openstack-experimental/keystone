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

//! `GET /v3/role_assignments` in its unfiltered form and each of the
//! `user.id` / `scope.domain.id` / `role.id` filter variants, exercising the
//! same seeded data (100 users granted the auth-project's `member` role) the
//! password-auth scenarios already rely on.

use goose::prelude::*;
use std::sync::OnceLock;

use crate::Session;

const DEFAULT_DOMAIN_ID: &str = "default";

static AUTH_ROLE_ID: OnceLock<String> = OnceLock::new();

/// Call once before `GooseAttack::execute()` to share the role every seeded
/// user is granted, for the `role.id` filter.
pub fn set_auth_role_id(id: String) {
    AUTH_ROLE_ID.set(id).ok();
}

async fn list_with_query(
    user: &mut GooseUser,
    name: &str,
    query: &[(&str, &str)],
) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let req = user
        .get_request_builder(&GooseMethod::Get, "/v3/role_assignments")?
        .header("x-auth-token", &token)
        .query(query);

    let goose_request = GooseRequest::builder()
        .name(name)
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// List all role assignments, unfiltered.
pub async fn list(user: &mut GooseUser) -> TransactionResult {
    list_with_query(user, "GET /v3/role_assignments", &[]).await
}

/// List role assignments filtered by a randomly chosen seeded user
/// (`user.id`). No-op if the seeded credential pool is empty.
pub async fn list_by_user(user: &mut GooseUser) -> TransactionResult {
    let Some(cred) = crate::v3::user::random_seeded_cred() else {
        return Ok(());
    };
    let user_id = cred.id.clone();
    list_with_query(
        user,
        "GET /v3/role_assignments?user.id",
        &[("user.id", &user_id)],
    )
    .await
}

/// List role assignments filtered by the default domain (`scope.domain.id`).
pub async fn list_by_domain(user: &mut GooseUser) -> TransactionResult {
    list_with_query(
        user,
        "GET /v3/role_assignments?scope.domain.id",
        &[("scope.domain.id", DEFAULT_DOMAIN_ID)],
    )
    .await
}

/// List role assignments filtered by the auth-project's `member` role
/// (`role.id`). No-op if seeding the auth role failed.
pub async fn list_by_role(user: &mut GooseUser) -> TransactionResult {
    let Some(role_id) = AUTH_ROLE_ID.get().cloned() else {
        return Ok(());
    };
    list_with_query(
        user,
        "GET /v3/role_assignments?role.id",
        &[("role.id", &role_id)],
    )
    .await
}
