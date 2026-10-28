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

//! High-cardinality churn: every iteration creates a fresh user and project,
//! grants a role, authenticates as that user (new identity, new token),
//! validates and revokes the token, then deletes everything. Any cache or
//! index keyed on ids that is never evicted grows with the iteration count.

use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::v3::role_assignment::auth_role_id;
use crate::v3::util::{
    DEFAULT_DOMAIN_ID, Undo, admin_token, call, create, create_user, password_auth_body,
};

pub async fn cycle(user: &mut GooseUser) -> TransactionResult {
    let mut undo = Undo::default();
    let res = run(user, &mut undo).await;
    undo.run(user).await;
    res
}

async fn run(user: &mut GooseUser, undo: &mut Undo) -> TransactionResult {
    let token = admin_token(user);
    let Some((user_id, password)) = create_user(user, undo).await? else {
        return Ok(());
    };
    let Some(project_id) = create(
        user,
        undo,
        "projects",
        "project",
        json!({"project": {
            "name": format!("loadtest-churn-{}", Uuid::new_v4().as_simple()),
            "domain_id": DEFAULT_DOMAIN_ID,
            "enabled": true,
        }}),
        "POST /v3/projects (churn)",
        "DELETE /v3/projects/:id (churn)",
    )
    .await?
    else {
        return Ok(());
    };

    let mut scope = None;
    if let Some(role_id) = auth_role_id() {
        let path = format!("/v3/projects/{project_id}/users/{user_id}/roles/{role_id}");
        if call(
            user,
            GooseMethod::Put,
            &path,
            "PUT /v3/projects/:id/users/:id/roles/:id (churn)",
            None,
            Some(&token),
        )
        .await?
        .is_some()
        {
            undo.push(path, "DELETE /v3/projects/:id/users/:id/roles/:id (churn)");
            scope = Some(project_id.as_str());
        }
    }

    let auth = password_auth_body(&user_id, &password, scope);
    let Some(subject) = call(
        user,
        GooseMethod::Post,
        "/v3/auth/tokens",
        "POST /v3/auth/tokens (churn user)",
        Some(&auth),
        None,
    )
    .await?
    .and_then(|r| r.subject_token) else {
        return Ok(());
    };

    for (method, name) in [
        (GooseMethod::Get, "GET /v3/auth/tokens (churn validate)"),
        (GooseMethod::Delete, "DELETE /v3/auth/tokens (churn)"),
    ] {
        let req = user
            .get_request_builder(&method, "/v3/auth/tokens")?
            .header("x-auth-token", &token)
            .header("x-subject-token", &subject);
        user.request(
            GooseRequest::builder()
                .name(name)
                .set_request_builder(req)
                .build(),
        )
        .await?;
    }
    Ok(())
}
