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
const SEED_USERS: usize = 100;
const SEED_PROJECTS: usize = 100;
/// Shared password for every seeded user, so password-auth scenarios can log
/// in as any user from the seeded pool without tracking per-user secrets.
pub const SEED_USER_PASSWORD: &str = "LoadTestSeedPassw0rd!";
/// Dedicated project all seeded users are granted a role on, used by the
/// project-scoped password auth scenarios.
const AUTH_PROJECT_NAME: &str = "loadtest-authproject";
const AUTH_ROLE_NAME: &str = "member";

/// A seeded user's credentials, usable for password authentication.
#[derive(Clone)]
pub struct SeededUserCred {
    pub id: String,
    pub password: String,
}

pub struct SeedState {
    pub user_ids: Vec<String>,
    pub project_ids: Vec<String>,
    /// Credentials for the seeded users, each holding a `member` role on
    /// `auth_project_id`.
    pub user_creds: Vec<SeededUserCred>,
    /// Project every seeded user has a role assignment on; used to exercise
    /// project-scoped password auth under load.
    pub auth_project_id: Option<String>,
    /// Role every seeded user is granted on `auth_project_id`; used to
    /// exercise the `role.id` filter on `GET /v3/role_assignments`.
    pub auth_role_id: Option<String>,
}

/// Create background resources so list endpoints return non-trivial result sets.
pub async fn seed(host: &str, token: &str) -> SeedState {
    let client = Client::new();
    let mut state = SeedState {
        user_ids: Vec::new(),
        project_ids: Vec::new(),
        user_creds: Vec::new(),
        auth_project_id: None,
        auth_role_id: None,
    };

    for i in 0..SEED_USERS {
        let name = format!("loadtest-seed-user-{}-{}", i, Uuid::new_v4().as_simple());
        match create_user(&client, host, token, &name, DEFAULT_DOMAIN_ID).await {
            Some(id) => {
                state.user_creds.push(SeededUserCred {
                    id: id.clone(),
                    password: SEED_USER_PASSWORD.to_string(),
                });
                state.user_ids.push(id);
            }
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

    match seed_auth_project(&client, host, token, &state.user_ids).await {
        Some((project_id, role_id)) => {
            eprintln!(
                "seed: created auth project {project_id} with {} user role assignments (role {role_id})",
                state.user_ids.len()
            );
            state.auth_project_id = Some(project_id);
            state.auth_role_id = Some(role_id);
        }
        None => eprintln!("seed: failed to set up auth project for password-auth scenarios"),
    }

    state
}

/// Create a dedicated project and grant every seeded user a `member` role on
/// it, so seeded users have a real scope to authenticate against. Returns
/// the project ID and the role ID granted to every user.
async fn seed_auth_project(
    client: &Client,
    host: &str,
    token: &str,
    user_ids: &[String],
) -> Option<(String, String)> {
    let project_id =
        create_project(client, host, token, AUTH_PROJECT_NAME, DEFAULT_DOMAIN_ID).await?;
    let role_id = get_or_create_role(client, host, token, AUTH_ROLE_NAME).await?;

    for user_id in user_ids {
        if let Err(e) =
            assign_project_role(client, host, token, &project_id, user_id, &role_id).await
        {
            eprintln!("seed: failed to assign role to user {user_id}: {e}");
        }
    }

    Some((project_id, role_id))
}

/// Find a role by name, creating it if it doesn't exist.
async fn get_or_create_role(
    client: &Client,
    host: &str,
    token: &str,
    name: &str,
) -> Option<String> {
    let resp = client
        .get(format!("{host}/v3/roles"))
        .header("x-auth-token", token)
        .query(&[("name", name)])
        .send()
        .await
        .ok()?;
    if resp.status().is_success() {
        let val: serde_json::Value = resp.json().await.ok()?;
        if let Some(id) = val["roles"][0]["id"].as_str() {
            return Some(id.to_owned());
        }
    }

    let body = json!({ "role": { "name": name } });
    let resp = client
        .post(format!("{host}/v3/roles"))
        .header("x-auth-token", token)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        eprintln!("seed: create_role HTTP {}", resp.status());
        return None;
    }
    let val: serde_json::Value = resp.json().await.ok()?;
    val["role"]["id"].as_str().map(str::to_owned)
}

/// Grant a user a role on a project.
async fn assign_project_role(
    client: &Client,
    host: &str,
    token: &str,
    project_id: &str,
    user_id: &str,
    role_id: &str,
) -> Result<(), reqwest::Error> {
    client
        .put(format!(
            "{host}/v3/projects/{project_id}/users/{user_id}/roles/{role_id}"
        ))
        .header("x-auth-token", token)
        .send()
        .await?;
    Ok(())
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

    if let Some(auth_project_id) = &state.auth_project_id
        && let Err(e) = delete(
            &client,
            host,
            token,
            &format!("/v3/projects/{auth_project_id}"),
        )
        .await
    {
        eprintln!("seed cleanup: failed to delete auth project {auth_project_id}: {e}");
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
            "password": SEED_USER_PASSWORD
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
