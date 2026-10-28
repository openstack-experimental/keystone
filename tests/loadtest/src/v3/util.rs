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

//! Helpers shared by the churn-style scenarios: a single request wrapper that
//! marks non-2xx replies as failures, and an undo stack so resources created
//! mid-iteration are removed even when a later step fails.

use goose::goose::TransactionError;
use goose::prelude::*;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::Session;

pub(crate) const DEFAULT_DOMAIN_ID: &str = "default";

/// Parsed reply of a successful request.
pub(crate) struct Reply {
    pub body: Value,
    /// Value of the `X-Subject-Token` response header, if any.
    pub subject_token: Option<String>,
}

/// Resources to delete (path, request name), removed in reverse order.
#[derive(Default)]
pub(crate) struct Undo(Vec<(String, &'static str)>);

impl Undo {
    pub fn push(&mut self, path: String, name: &'static str) {
        self.0.push((path, name));
    }

    /// Best-effort removal; failures are only visible in goose's stats.
    pub async fn run(&mut self, user: &mut GooseUser) {
        let token = admin_token(user);
        while let Some((path, name)) = self.0.pop() {
            let _ = call(user, GooseMethod::Delete, &path, name, None, Some(&token)).await;
        }
    }
}

/// Admin token of the virtual user.
pub(crate) fn admin_token(user: &GooseUser) -> String {
    user.get_session_data_unchecked::<Session>().token.clone()
}

/// Send one request. A transport error or non-2xx status is recorded as a
/// goose failure; `Ok(None)` is only returned if goose did not turn that into
/// an error.
pub(crate) async fn call(
    user: &mut GooseUser,
    method: GooseMethod,
    path: &str,
    name: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> Result<Option<Reply>, Box<TransactionError>> {
    let mut req = user.get_request_builder(&method, path)?;
    if let Some(token) = token {
        req = req.header("x-auth-token", token);
    }
    if let Some(body) = body {
        req = req.json(body);
    }
    let goose_request = GooseRequest::builder()
        .name(name)
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            user.set_failure(
                &format!("{name} failed: {e}"),
                &mut goose.request,
                None,
                None,
            )?;
            return Ok(None);
        }
    };
    let status = response.status();
    if !status.is_success() {
        user.set_failure(
            &format!("{name} returned {status}"),
            &mut goose.request,
            None,
            None,
        )?;
        return Ok(None);
    }
    let subject_token = response
        .headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response.json().await.unwrap_or_default();
    Ok(Some(Reply {
        body,
        subject_token,
    }))
}

/// POST a resource and register its deletion. Returns the new id.
pub(crate) async fn create(
    user: &mut GooseUser,
    undo: &mut Undo,
    collection: &str,
    key: &str,
    body: Value,
    create_name: &str,
    delete_name: &'static str,
) -> Result<Option<String>, Box<TransactionError>> {
    let token = admin_token(user);
    let path = format!("/v3/{collection}");
    let Some(reply) = call(
        user,
        GooseMethod::Post,
        &path,
        create_name,
        Some(&body),
        Some(&token),
    )
    .await?
    else {
        return Ok(None);
    };
    let Some(id) = reply.body[key]["id"].as_str().map(str::to_owned) else {
        return Ok(None);
    };
    undo.push(format!("{path}/{id}"), delete_name);
    Ok(Some(id))
}

/// Create a user with a random password. Returns (id, password).
pub(crate) async fn create_user(
    user: &mut GooseUser,
    undo: &mut Undo,
) -> Result<Option<(String, String)>, Box<TransactionError>> {
    let password = Uuid::new_v4().to_string();
    let body = json!({"user": {
        "name": format!("loadtest-churn-{}", Uuid::new_v4().as_simple()),
        "domain_id": DEFAULT_DOMAIN_ID,
        "enabled": true,
        "password": password,
    }});
    Ok(create(
        user,
        undo,
        "users",
        "user",
        body,
        "POST /v3/users (churn)",
        "DELETE /v3/users/:id (churn)",
    )
    .await?
    .map(|id| (id, password)))
}

/// Password-auth body for a user id, optionally scoped to a project.
pub(crate) fn password_auth_body(id: &str, password: &str, project_id: Option<&str>) -> Value {
    let mut auth = json!({"identity": {
        "methods": ["password"],
        "password": {"user": {"id": id, "password": password}},
    }});
    if let Some(project_id) = project_id {
        auth["scope"] = json!({"project": {"id": project_id}});
    }
    json!({ "auth": auth })
}
