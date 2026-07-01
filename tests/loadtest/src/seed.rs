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

//! Global seed: pre-populates the database before the attack begins so that
//! list endpoints operate on realistic data volumes.  All created resources
//! are deleted after the attack completes.

use reqwest::Client;
use serde_json::json;
use uuid::Uuid;

const DEFAULT_DOMAIN_ID: &str = "default";
const SEED_USERS: usize = 20;
const SEED_PROJECTS: usize = 10;

pub struct SeedState {
    pub user_ids: Vec<String>,
    pub project_ids: Vec<String>,
}

/// Create background resources so list endpoints return non-trivial result sets.
pub async fn seed(host: &str, token: &str) -> SeedState {
    let client = Client::new();
    let mut state = SeedState {
        user_ids: Vec::new(),
        project_ids: Vec::new(),
    };

    for i in 0..SEED_USERS {
        let name = format!("loadtest-seed-user-{}-{}", i, Uuid::new_v4().as_simple());
        match create_user(&client, host, token, &name, DEFAULT_DOMAIN_ID).await {
            Some(id) => state.user_ids.push(id),
            None => eprintln!("seed: failed to create user {name}"),
        }
    }

    for i in 0..SEED_PROJECTS {
        let name = format!("loadtest-seed-project-{}-{}", i, Uuid::new_v4().as_simple());
        match create_project(&client, host, token, &name, DEFAULT_DOMAIN_ID).await {
            Some(id) => state.project_ids.push(id),
            None => eprintln!("seed: failed to create project {name}"),
        }
    }

    eprintln!(
        "seed: created {} users, {} projects",
        state.user_ids.len(),
        state.project_ids.len()
    );

    state
}

/// Delete all resources created during seeding.
pub async fn cleanup(host: &str, token: &str, state: &SeedState) {
    let client = Client::new();

    for id in &state.user_ids {
        if let Err(e) = delete(&client, host, token, &format!("/v3/users/{id}")).await {
            eprintln!("seed cleanup: failed to delete user {id}: {e}");
        }
    }

    for id in &state.project_ids {
        if let Err(e) = delete(&client, host, token, &format!("/v3/projects/{id}")).await {
            eprintln!("seed cleanup: failed to delete project {id}: {e}");
        }
    }

    eprintln!(
        "seed cleanup: removed {} users, {} projects",
        state.user_ids.len(),
        state.project_ids.len()
    );
}

async fn create_user(
    client: &Client,
    host: &str,
    token: &str,
    name: &str,
    domain_id: &str,
) -> Option<String> {
    let body = json!({
        "user": {
            "name": name,
            "domain_id": domain_id,
            "enabled": true,
            "password": Uuid::new_v4().to_string()
        }
    });
    let resp = client
        .post(format!("{host}/v3/users"))
        .header("x-auth-token", token)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        eprintln!("seed: create_user HTTP {}", resp.status());
        return None;
    }
    let val: serde_json::Value = resp.json().await.ok()?;
    val["user"]["id"].as_str().map(str::to_owned)
}

async fn create_project(
    client: &Client,
    host: &str,
    token: &str,
    name: &str,
    domain_id: &str,
) -> Option<String> {
    let body = json!({
        "project": {
            "name": name,
            "domain_id": domain_id,
            "enabled": true,
            "is_domain": false
        }
    });
    let resp = client
        .post(format!("{host}/v3/projects"))
        .header("x-auth-token", token)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        eprintln!("seed: create_project HTTP {}", resp.status());
        return None;
    }
    let val: serde_json::Value = resp.json().await.ok()?;
    val["project"]["id"].as_str().map(str::to_owned)
}

async fn delete(
    client: &Client,
    host: &str,
    token: &str,
    path: &str,
) -> Result<(), reqwest::Error> {
    client
        .delete(format!("{host}{path}"))
        .header("x-auth-token", token)
        .send()
        .await?;
    Ok(())
}
