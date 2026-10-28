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

//! Group churn: create, show, update, list and delete in every iteration.
//! (Group membership is not served by keystone-rs yet, so it is not covered.)

use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::v3::util::{DEFAULT_DOMAIN_ID, Undo, admin_token, call, create};

pub async fn cycle(user: &mut GooseUser) -> TransactionResult {
    let mut undo = Undo::default();
    let res = run(user, &mut undo).await;
    undo.run(user).await;
    res
}

async fn run(user: &mut GooseUser, undo: &mut Undo) -> TransactionResult {
    let token = admin_token(user);
    let body = json!({"group": {
        "name": format!("loadtest-group-{}", Uuid::new_v4().as_simple()),
        "domain_id": DEFAULT_DOMAIN_ID,
        "description": "loadtest group",
    }});
    let Some(id) = create(
        user,
        undo,
        "groups",
        "group",
        body,
        "POST /v3/groups",
        "DELETE /v3/groups/:id",
    )
    .await?
    else {
        return Ok(());
    };
    let path = format!("/v3/groups/{id}");
    call(
        user,
        GooseMethod::Get,
        &path,
        "GET /v3/groups/:id",
        None,
        Some(&token),
    )
    .await?;
    let patch = json!({"group": {"description": Uuid::new_v4().to_string()}});
    call(
        user,
        GooseMethod::Patch,
        &path,
        "PATCH /v3/groups/:id",
        Some(&patch),
        Some(&token),
    )
    .await?;
    call(
        user,
        GooseMethod::Get,
        "/v3/groups?domain_id=default",
        "GET /v3/groups",
        None,
        Some(&token),
    )
    .await?;
    Ok(())
}
