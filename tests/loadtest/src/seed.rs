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
const SCIM_IDP_NAME: &str = "loadtest-scim-idp";
const SCIM_REALM_PROVIDER_ID: &str = "loadtest-scim-realm";

/// A seeded user's credentials, usable for password authentication.
#[derive(Clone)]
pub struct SeededUserCred {
    pub id: String,
    pub password: String,
}

/// OAuth2 resources the token-minting scenarios run against. They live in a
/// dedicated domain because `default` is seeded straight into the DB, never
/// fires the key-provisioning hook, and so can never sign a token.
#[derive(Clone)]
pub struct Oauth2Seed {
    pub domain_id: String,
    /// `client_id` of a public `device_code` client.
    pub device_client_id: String,
    pub device_provider_id: String,
    /// `reader` role granted by the per-VU rulesets.
    pub reader_role_id: String,
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
    /// Federation identity provider backing `scim_realm_provider_id`, used by
    /// the SCIM realm loadtest scenario (ADR 0024). SCIM realms cannot be
    /// created without a real, existing IdP (`get_identity_provider` check).
    pub scim_idp_id: Option<String>,
    /// `provider_id` of the SCIM realm seeded for `ScimRealmRead`. There is
    /// no realm-delete endpoint (only per-resource purge), so this realm is
    /// not torn down -- only the backing IdP is, best-effort, in `cleanup`.
    pub scim_realm_provider_id: Option<String>,
    /// Domain, clients and mapping ruleset for the OAuth2 token scenarios.
    pub oauth2: Option<Oauth2Seed>,
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
        scim_idp_id: None,
        scim_realm_provider_id: None,
        oauth2: None,
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

    match seed_scim_realm(&client, host, token).await {
        Some((idp_id, provider_id)) => {
            eprintln!("seed: created SCIM idp {idp_id} + realm {provider_id}");
            state.scim_idp_id = Some(idp_id);
            state.scim_realm_provider_id = Some(provider_id);
        }
        None => eprintln!("seed: failed to set up SCIM idp/realm for ScimRealmRead scenario"),
    }

    match seed_oauth2(&client, host, token).await {
        Some(seeded) => {
            eprintln!("seed: created OAuth2 domain {}", seeded.domain_id);
            state.oauth2 = Some(seeded);
        }
        None => eprintln!("seed: failed to set up OAuth2 domain/clients for the token scenarios"),
    }

    state
}

/// Create a global federation IdP and a SCIM realm bound to it, so the SCIM
/// realm loadtest scenario (raft-backed, ADR 0024) has a real realm to read.
/// `create_realm` 404s unless the referenced `idp_id` already resolves via
/// `get_identity_provider`, so the IdP must exist first.
async fn seed_scim_realm(client: &Client, host: &str, token: &str) -> Option<(String, String)> {
    let idp_body = json!({
        "identity_provider": {
            "name": SCIM_IDP_NAME,
            "domain_id": DEFAULT_DOMAIN_ID
        }
    });
    let resp = client
        .post(format!("{host}/v4/federation/identity_providers"))
        .header("x-auth-token", token)
        .json(&idp_body)
        .send()
        .await
        .ok()?;
    let idp_id = if resp.status() == reqwest::StatusCode::CONFLICT {
        // A prior interrupted run's IdP survived cleanup -- reuse it by name
        // rather than aborting seed setup.
        let resp = client
            .get(format!(
                "{host}/v4/federation/identity_providers?domain_id={DEFAULT_DOMAIN_ID}"
            ))
            .header("x-auth-token", token)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            eprintln!("seed: list identity_providers HTTP {}", resp.status());
            return None;
        }
        let val: serde_json::Value = resp.json().await.ok()?;
        val["identity_providers"]
            .as_array()?
            .iter()
            .find(|idp| idp["name"].as_str() == Some(SCIM_IDP_NAME))?["id"]
            .as_str()?
            .to_owned()
    } else {
        if !resp.status().is_success() {
            eprintln!("seed: create identity_provider HTTP {}", resp.status());
            return None;
        }
        let val: serde_json::Value = resp.json().await.ok()?;
        val["identity_provider"]["id"].as_str()?.to_owned()
    };

    let realm_body = json!({
        "scim_realm": {
            "domain_id": DEFAULT_DOMAIN_ID,
            "provider_id": SCIM_REALM_PROVIDER_ID,
            "idp_id": idp_id,
            "display_name": "Loadtest SCIM realm"
        }
    });
    let resp = client
        .post(format!("{host}/v4/scim_realms"))
        .header("x-auth-token", token)
        .json(&realm_body)
        .send()
        .await
        .ok()?;
    if resp.status() == reqwest::StatusCode::CONFLICT {
        // A prior run's realm survived (no delete endpoint exists for it,
        // ADR 0024) -- reuse it rather than aborting seed setup.
        let resp = client
            .get(format!(
                "{host}/v4/scim_realms/{DEFAULT_DOMAIN_ID}/{SCIM_REALM_PROVIDER_ID}"
            ))
            .header("x-auth-token", token)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            eprintln!("seed: fetch existing scim_realm HTTP {}", resp.status());
            return None;
        }
        let val: serde_json::Value = resp.json().await.ok()?;
        let existing_idp_id = val["scim_realm"]["idp_id"].as_str()?.to_owned();
        let provider_id = val["scim_realm"]["provider_id"].as_str()?.to_owned();
        return Some((existing_idp_id, provider_id));
    }
    if !resp.status().is_success() {
        eprintln!("seed: create scim_realm HTTP {}", resp.status());
        return None;
    }
    let val: serde_json::Value = resp.json().await.ok()?;
    let provider_id = val["scim_realm"]["provider_id"].as_str()?.to_owned();

    Some((idp_id, provider_id))
}

/// Create a domain with OAuth2 signing keys and a public `device_code`
/// client; look up the `reader` role the per-VU rulesets grant.
async fn seed_oauth2(client: &Client, host: &str, token: &str) -> Option<Oauth2Seed> {
    let suffix = Uuid::new_v4().as_simple().to_string();
    let resp = client
        .post(format!("{host}/v3/domains"))
        .header("x-auth-token", token)
        .json(&json!({"domain": {"name": format!("loadtest-oauth2-{suffix}"), "enabled": true}}))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        eprintln!("seed: create oauth2 domain HTTP {}", resp.status());
        return None;
    }
    let val: serde_json::Value = resp.json().await.ok()?;
    let domain_id = val["domain"]["id"].as_str()?.to_owned();

    // Key provisioning runs asynchronously after domain creation.
    let mut ready = false;
    for _ in 0..80 {
        let resp = client
            .get(format!(
                "{host}/v4/oauth2/{domain_id}/.well-known/openid-configuration"
            ))
            .send()
            .await
            .ok()?;
        if resp.status().is_success() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if !ready {
        eprintln!("seed: OAuth2 signing keys for domain {domain_id} never appeared");
        return None;
    }

    let device_provider_id = format!("loadtest-device-{suffix}");
    let (device_client_id, _) = create_oauth2_client(
        client,
        host,
        token,
        &domain_id,
        json!({
            "provider_id": device_provider_id,
            "name": "Load test device",
            "confidential": false,
            "grant_types": ["device_code"],
            "allowed_scopes": ["openid"],
            "token_endpoint_auth_method": "none",
            "require_pkce": true,
        }),
    )
    .await?;

    let resp = client
        .get(format!("{host}/v3/roles?name=reader"))
        .header("x-auth-token", token)
        .send()
        .await
        .ok()?;
    let val: serde_json::Value = resp.json().await.ok()?;
    let role_id = val["roles"][0]["id"].as_str()?.to_owned();

    Some(Oauth2Seed {
        domain_id,
        device_client_id,
        device_provider_id,
        reader_role_id: role_id,
    })
}

/// Register an OAuth2 client; returns `(client_id, client_secret)`, with an
/// empty secret for public clients.
async fn create_oauth2_client(
    client: &Client,
    host: &str,
    token: &str,
    domain_id: &str,
    body: serde_json::Value,
) -> Option<(String, String)> {
    let resp = client
        .post(format!("{host}/v4/oauth2/{domain_id}/clients"))
        .header("x-auth-token", token)
        .json(&json!({ "oauth2_client": body }))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        let status = resp.status();
        let detail = resp.text().await.unwrap_or_default();
        eprintln!("seed: create oauth2 client HTTP {status}: {detail}");
        return None;
    }
    let val: serde_json::Value = resp.json().await.ok()?;
    Some((
        val["oauth2_client"]["client_id"].as_str()?.to_owned(),
        val["client_secret"].as_str().unwrap_or_default().to_owned(),
    ))
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
        get_or_create_project(client, host, token, AUTH_PROJECT_NAME, DEFAULT_DOMAIN_ID).await?;
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

/// Find a project by name, creating it if it doesn't exist.
///
/// The project has a fixed name, so one left behind by a run that was killed
/// before its cleanup would make a plain create fail with 409.
async fn get_or_create_project(
    client: &Client,
    host: &str,
    token: &str,
    name: &str,
    domain_id: &str,
) -> Option<String> {
    let resp = client
        .get(format!("{host}/v3/projects"))
        .header("x-auth-token", token)
        .query(&[("name", name), ("domain_id", domain_id)])
        .send()
        .await
        .ok()?;
    if resp.status().is_success() {
        let val: serde_json::Value = resp.json().await.ok()?;
        if let Some(id) = val["projects"][0]["id"].as_str() {
            return Some(id.to_owned());
        }
    }
    create_project(client, host, token, name, domain_id).await
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

    if let Some(idp_id) = &state.scim_idp_id
        && let Err(e) = delete(
            &client,
            host,
            token,
            &format!("/v4/federation/identity_providers/{idp_id}"),
        )
        .await
    {
        eprintln!("seed cleanup: failed to delete scim idp {idp_id}: {e}");
    }

    if let Some(oauth2) = &state.oauth2 {
        let domain = &oauth2.domain_id;
        for path in [format!(
            "/v4/oauth2/{domain}/clients/{}",
            oauth2.device_provider_id
        )] {
            if let Err(e) = delete(&client, host, token, &path).await {
                eprintln!("seed cleanup: failed to delete {path}: {e}");
            }
        }
        // A domain must be disabled before it can be deleted.
        if let Err(e) = client
            .patch(format!("{host}/v3/domains/{domain}"))
            .header("x-auth-token", token)
            .json(&json!({"domain": {"enabled": false}}))
            .send()
            .await
        {
            eprintln!("seed cleanup: failed to disable oauth2 domain {domain}: {e}");
        } else if let Err(e) = delete(&client, host, token, &format!("/v3/domains/{domain}")).await
        {
            eprintln!("seed cleanup: failed to delete oauth2 domain {domain}: {e}");
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
