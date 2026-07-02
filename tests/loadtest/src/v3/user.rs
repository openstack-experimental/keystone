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

use goose::prelude::*;
use serde_json::json;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::Session;

const DEFAULT_DOMAIN_ID: &str = "default";

static SEEDED_USER_IDS: OnceLock<Vec<String>> = OnceLock::new();

/// Call once before `GooseAttack::execute()` to share the seeded user ID pool
/// with all virtual users.
pub fn set_seeded_ids(ids: Vec<String>) {
    SEEDED_USER_IDS.set(ids).ok();
}

/// List all users (read-heavy scenario transaction).
pub async fn list(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let req = user
        .get_request_builder(&GooseMethod::Get, "/v3/users")?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder().set_request_builder(req).build();

    user.request(goose_request).await?;
    Ok(())
}

/// Show a randomly chosen user from the pre-seeded pool.
///
/// Measures GET /v3/users/:id latency against a realistic, pre-populated dataset.
/// Returns Ok(()) silently if the pool is empty (seed failed entirely).
pub async fn show_random(user: &mut GooseUser) -> TransactionResult {
    let ids = match SEEDED_USER_IDS.get() {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(()),
    };
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let id = &ids[fastrand::usize(..ids.len())];
    let path = format!("/v3/users/{id}");

    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v3/users/:id (catalog)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Create a user owned by this virtual user (on_start for UserCRUD scenario).
pub async fn create(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let name = format!("loadtest-user-{}", Uuid::new_v4().as_simple());
    let body = json!({
        "user": {
            "name": name,
            "domain_id": DEFAULT_DOMAIN_ID,
            "enabled": true,
            "password": Uuid::new_v4().to_string()
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/users")?
        .header("x-auth-token", &token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/users (setup)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("user create failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };

    if !response.status().is_success() {
        return user.set_failure(
            &format!("user create returned {}", response.status()),
            &mut goose.request,
            None,
            None,
        );
    }

    let val: serde_json::Value = response.json().await.unwrap_or_default();
    let user_id = val["user"]["id"].as_str().map(str::to_owned);

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.user_id = user_id;

    Ok(())
}

/// Show the user owned by this virtual user.
pub async fn show(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let user_id = match &session.user_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v3/users/{user_id}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v3/users/:id")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Delete the user owned by this virtual user (on_stop for UserCRUD scenario).
pub async fn delete(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let user_id = match &session.user_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v3/users/{user_id}");
    let req = user
        .get_request_builder(&GooseMethod::Delete, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("DELETE /v3/users/:id (teardown)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.user_id = None;

    Ok(())
}
