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
use uuid::Uuid;

use crate::Session;

const DEFAULT_DOMAIN_ID: &str = "default";

/// List all projects (read-heavy scenario transaction).
pub async fn list(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let req = user
        .get_request_builder(&GooseMethod::Get, "/v3/projects")?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Create a project owned by this virtual user (on_start for ProjectCRUD scenario).
pub async fn create(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();

    let name = format!("loadtest-project-{}", Uuid::new_v4().as_simple());
    let body = json!({
        "project": {
            "name": name,
            "domain_id": DEFAULT_DOMAIN_ID,
            "enabled": true,
            "is_domain": false
        }
    });

    let req = user
        .get_request_builder(&GooseMethod::Post, "/v3/projects")?
        .header("x-auth-token", &token)
        .json(&body);

    let goose_request = GooseRequest::builder()
        .name("POST /v3/projects (setup)")
        .set_request_builder(req)
        .build();

    let mut goose = user.request(goose_request).await?;
    let response = match goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                &format!("project create failed: {e}"),
                &mut goose.request,
                None,
                None,
            );
        }
    };

    if !response.status().is_success() {
        return user.set_failure(
            &format!("project create returned {}", response.status()),
            &mut goose.request,
            None,
            None,
        );
    }

    let val: serde_json::Value = response.json().await.unwrap_or_default();
    let project_id = val["project"]["id"].as_str().map(str::to_owned);

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.project_id = project_id;

    Ok(())
}

/// Show the project owned by this virtual user.
pub async fn show(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let project_id = match &session.project_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v3/projects/{project_id}");
    let req = user
        .get_request_builder(&GooseMethod::Get, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("GET /v3/projects/:id")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;
    Ok(())
}

/// Delete the project owned by this virtual user (on_stop for ProjectCRUD scenario).
pub async fn delete(user: &mut GooseUser) -> TransactionResult {
    let session = user.get_session_data_unchecked::<Session>();
    let token = session.token.clone();
    let project_id = match &session.project_id {
        Some(id) => id.clone(),
        None => return Ok(()),
    };

    let path = format!("/v3/projects/{project_id}");
    let req = user
        .get_request_builder(&GooseMethod::Delete, &path)?
        .header("x-auth-token", &token);

    let goose_request = GooseRequest::builder()
        .name("DELETE /v3/projects/:id (teardown)")
        .set_request_builder(req)
        .build();

    user.request(goose_request).await?;

    let session = user.get_session_data_unchecked_mut::<Session>();
    session.project_id = None;

    Ok(())
}
