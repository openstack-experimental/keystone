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

//! `LOADTEST_PROFILE=vu`: every virtual user is one typical end user of the
//! cloud, living in a tenant of its own.
//!
//! Before the measurement starts [`bootstrap`] creates a domain per ten
//! virtual users and spreads the users over the domains. Each of them gets a
//! user with a password, two projects, a group, a role on both projects and an
//! application credential. During the run a virtual user only ever acts as that
//! user.
//!
//! Share of the operations (the `LOADTEST_VU_*_PCT` variables override the
//! shares named below; the rest is split 3:3:1 between the rescope, the
//! `GET /v3/auth/projects` and the application credential list):
//! - 75% token validation (`LOADTEST_VU_VALIDATE_PCT`): the **admin**
//!   validates a token of the virtual user (`nocatalog`, as a service checking
//!   the tokens of its clients does). No client side token cache is assumed.
//! - 13% administrative reads (`LOADTEST_VU_ADMIN_READ_PCT`), the way a
//!   Terraform refresh or a dashboard reads: get project, user, group, role,
//!   list (effective) role assignments, list projects and users of a domain
//! - 3% logins (`LOADTEST_VU_HASH_PCT`), password and application credential
//!   2:1; both hash a password on the server
//! - 2% role assignment writes (`LOADTEST_VU_ASSIGN_PCT`): grant a role that
//!   already exists (what Terraform does on every apply, 3 of 4) or check an
//!   assignment (`HEAD`, 1 of 4)
//! - 0.2% creation of a project or a role (`LOADTEST_VU_CREATE_PCT`)
//! - 0.02% deletions (`LOADTEST_VU_REVOKE_PCT`): delete a token, remove a role
//!   assignment, remove a user from a group, delete a project, delete a role.
//!   Each creates revocation records, which a real cloud rarely does and which
//!   grow the revocation table, so the share is kept tiny.
//!   `LOADTEST_VU_REVOKE_OP=0..4` restricts them to one operation.
//!
//! Operations never produce an expected failure: deletions and removals act on
//! a scratch user, project and group of the virtual user, never on the ones
//! whose tokens are validated. Every non 2xx response is therefore a failure
//! in the report.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use goose::prelude::*;
use reqwest::Client;
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Virtual users per domain.
const USERS_PER_DOMAIN: usize = 10;
/// Concurrent requests of the bootstrap and the cleanup.
const SETUP_CONCURRENCY: usize = 16;
/// Tokens a virtual user keeps at most.
const MAX_TOKENS: usize = 4;
const PASSWORD: &str = "LoadTestVuPassw0rd!";

/// Everything a virtual user needs, created by [`bootstrap`].
#[derive(Clone)]
pub struct VuSeed {
    pub user_id: String,
    pub user_name: String,
    pub domain_id: String,
    /// The project the user logs in to and a second one to rescope to.
    pub project_ids: [String; 2],
    pub group_id: String,
    pub role_id: String,
    pub app_cred_id: String,
    pub app_cred_secret: String,
    /// A user with a project and a group that revocation operations act on, so
    /// the tokens of `user_id` are never revoked.
    pub scratch_user_id: String,
    pub scratch_project_id: String,
    pub scratch_group_id: String,
}

/// What [`bootstrap`] created.
pub struct VuBootstrap {
    pub seeds: Vec<VuSeed>,
    domain_ids: Vec<String>,
}

static SEEDS: OnceLock<Vec<VuSeed>> = OnceLock::new();
static ADMIN_TOKEN: OnceLock<String> = OnceLock::new();
static NEXT_SEED: AtomicUsize = AtomicUsize::new(0);
/// Roles created during the run, deleted by [`cleanup`].
static CREATED_ROLES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Hand the bootstrap result to the virtual users.
pub fn share(bootstrap: &VuBootstrap, admin_token: &str) {
    SEEDS.set(bootstrap.seeds.clone()).ok();
    ADMIN_TOKEN.set(admin_token.to_string()).ok();
}

/// Session data of a virtual user.
#[derive(Clone)]
struct VuSession {
    seed: VuSeed,
    /// Valid-looking tokens of the user, the oldest first.
    tokens: Vec<String>,
    /// The tokens that can be rescoped: those issued by a password login (and
    /// their rescopes). Rescoping a token of an application credential is
    /// forbidden by design.
    rescopable: Vec<String>,
    /// Audit ids, issue time and origin of the tokens, logged when the server
    /// rejects one of them (see `trace_reject`).
    info: std::collections::HashMap<String, String>,
}

fn admin_token() -> &'static str {
    ADMIN_TOKEN.get().map_or("", String::as_str)
}

fn pct(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| (0.0..=100.0).contains(v))
        .unwrap_or(default)
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().as_simple())
}

// ---------------------------------------------------------------------------
// Bootstrap and cleanup (plain HTTP, outside of the measured run)
// ---------------------------------------------------------------------------

async fn send_json(
    client: &Client,
    method: reqwest::Method,
    url: String,
    token: &str,
    body: Option<Value>,
) -> Option<(u16, Option<String>, Value)> {
    let mut req = client.request(method, url).header("x-auth-token", token);
    if let Some(body) = body {
        req = req.json(&body);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vu bootstrap: request failed: {e:?}");
            return None;
        }
    };
    let status = resp.status().as_u16();
    let subject = resp
        .headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp.json::<Value>().await.unwrap_or(Value::Null);
    Some((status, subject, body))
}

async fn create(
    client: &Client,
    host: &str,
    token: &str,
    path: &str,
    key: &str,
    body: Value,
) -> Option<String> {
    let (status, _, value) = send_json(
        client,
        reqwest::Method::POST,
        format!("{host}{path}"),
        token,
        Some(body),
    )
    .await?;
    if !(200..300).contains(&status) {
        eprintln!("vu bootstrap: POST {path} returned {status}");
        return None;
    }
    value[key]["id"].as_str().map(str::to_string)
}

async fn put(client: &Client, host: &str, token: &str, path: &str) -> bool {
    send_json(
        client,
        reqwest::Method::PUT,
        format!("{host}{path}"),
        token,
        None,
    )
    .await
    .is_some_and(|(status, _, body)| {
        if !(200..300).contains(&status) {
            eprintln!("vu bootstrap: PUT {path} returned {status}: {body}");
        }
        (200..300).contains(&status)
    })
}

async fn find_member_role(client: &Client, host: &str, token: &str) -> Option<String> {
    let (_, _, value) = send_json(
        client,
        reqwest::Method::GET,
        format!("{host}/v3/roles?name=member"),
        token,
        None,
    )
    .await?;
    if let Some(id) = value["roles"][0]["id"].as_str() {
        return Some(id.to_string());
    }
    create(
        client,
        host,
        token,
        "/v3/roles",
        "role",
        json!({"role": {"name": "member"}}),
    )
    .await
}

async fn seed_one(
    client: &Client,
    host: &str,
    token: &str,
    domain_id: &str,
    role_id: &str,
    index: usize,
) -> Option<VuSeed> {
    let user_name = unique(&format!("vu-user-{index}"));
    let user_id = create(
        client,
        host,
        token,
        "/v3/users",
        "user",
        json!({"user": {
            "name": user_name,
            "domain_id": domain_id,
            "enabled": true,
            "password": PASSWORD,
        }}),
    )
    .await?;
    let mut project_ids = Vec::new();
    for n in 0..2 {
        let id = create(
            client,
            host,
            token,
            "/v3/projects",
            "project",
            json!({"project": {
                "name": unique(&format!("vu-project-{index}-{n}")),
                "domain_id": domain_id,
                "enabled": true,
            }}),
        )
        .await?;
        if !put(
            client,
            host,
            token,
            &format!("/v3/projects/{id}/users/{user_id}/roles/{role_id}"),
        )
        .await
        {
            eprintln!("vu bootstrap: cannot assign the role on {id}");
            return None;
        }
        project_ids.push(id);
    }
    let group_id = create(
        client,
        host,
        token,
        "/v3/groups",
        "group",
        json!({"group": {"name": unique(&format!("vu-group-{index}")), "domain_id": domain_id}}),
    )
    .await?;
    if !put(
        client,
        host,
        token,
        &format!("/v3/groups/{group_id}/users/{user_id}"),
    )
    .await
    {
        eprintln!("vu bootstrap: cannot add the user to the group");
        return None;
    }

    let scratch_user_id = create(
        client,
        host,
        token,
        "/v3/users",
        "user",
        json!({"user": {
            "name": unique(&format!("vu-scratch-user-{index}")),
            "domain_id": domain_id,
            "enabled": true,
            "password": PASSWORD,
        }}),
    )
    .await?;
    let scratch_project_id = create(
        client,
        host,
        token,
        "/v3/projects",
        "project",
        json!({"project": {
            "name": unique(&format!("vu-scratch-project-{index}")),
            "domain_id": domain_id,
            "enabled": true,
        }}),
    )
    .await?;
    let scratch_group_id = create(
        client,
        host,
        token,
        "/v3/groups",
        "group",
        json!({"group": {"name": unique(&format!("vu-scratch-group-{index}")), "domain_id": domain_id}}),
    )
    .await?;
    if !put(
        client,
        host,
        token,
        &format!("/v3/projects/{scratch_project_id}/users/{scratch_user_id}/roles/{role_id}"),
    )
    .await
        || !put(
            client,
            host,
            token,
            &format!("/v3/groups/{scratch_group_id}/users/{scratch_user_id}"),
        )
        .await
    {
        eprintln!("vu bootstrap: cannot set up the scratch user");
        return None;
    }

    // The application credential belongs to the user: log in as that user.
    let (status, subject, _) = send_json(
        client,
        reqwest::Method::POST,
        format!("{host}/v3/auth/tokens"),
        "",
        Some(password_body(&user_name, domain_id, Some(&project_ids[0]))),
    )
    .await?;
    let user_token = subject.filter(|_| status == 201)?;
    let (status, _, value) = send_json(
        client,
        reqwest::Method::POST,
        format!("{host}/v3/users/{user_id}/application_credentials"),
        &user_token,
        Some(json!({"application_credential": {
            "name": unique("vu-app-cred"),
            "roles": [{"id": role_id}],
        }})),
    )
    .await?;
    if status != 201 {
        eprintln!("vu bootstrap: application credential returned {status}");
        return None;
    }
    let app_cred = &value["application_credential"];
    Some(VuSeed {
        user_id,
        user_name,
        domain_id: domain_id.to_string(),
        project_ids: [project_ids[0].clone(), project_ids[1].clone()],
        group_id,
        role_id: role_id.to_string(),
        app_cred_id: app_cred["id"].as_str()?.to_string(),
        app_cred_secret: app_cred["secret"].as_str()?.to_string(),
        scratch_user_id,
        scratch_project_id,
        scratch_group_id,
    })
}

/// Create the domains (one per ten virtual users) and everything the virtual
/// users act on. Users are spread over the domains round robin.
pub async fn bootstrap(host: &str, token: &str, users: usize) -> VuBootstrap {
    let client = Client::new();
    let domains = users.div_ceil(USERS_PER_DOMAIN).max(1);
    let mut domain_ids = Vec::new();
    for n in 0..domains {
        if let Some(id) = create(
            &client,
            host,
            token,
            "/v3/domains",
            "domain",
            json!({"domain": {"name": unique(&format!("vu-domain-{n}")), "enabled": true}}),
        )
        .await
        {
            domain_ids.push(id);
        }
    }
    let Some(role_id) = find_member_role(&client, host, token).await else {
        eprintln!("vu bootstrap: no member role");
        return VuBootstrap {
            seeds: Vec::new(),
            domain_ids,
        };
    };
    if domain_ids.is_empty() {
        eprintln!("vu bootstrap: no domain created");
        return VuBootstrap {
            seeds: Vec::new(),
            domain_ids,
        };
    }

    let permits = std::sync::Arc::new(Semaphore::new(SETUP_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for index in 0..users {
        let (client, host, token, role_id) = (
            client.clone(),
            host.to_string(),
            token.to_string(),
            role_id.clone(),
        );
        let domain_id = domain_ids[index % domain_ids.len()].clone();
        let permits = permits.clone();
        set.spawn(async move {
            let _permit = permits.acquire_owned().await.ok()?;
            seed_one(&client, &host, &token, &domain_id, &role_id, index).await
        });
    }
    let mut seeds = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(seed)) = res {
            seeds.push(seed);
        }
    }
    eprintln!(
        "vu bootstrap: {} of {users} virtual users in {} domains",
        seeds.len(),
        domain_ids.len()
    );
    VuBootstrap { seeds, domain_ids }
}

async fn delete_listed(
    client: &Client,
    host: &str,
    token: &str,
    list: &str,
    key: &str,
    item: &str,
) {
    for _ in 0..200 {
        let Some((_, _, value)) = send_json(
            client,
            reqwest::Method::GET,
            format!("{host}{list}"),
            token,
            None,
        )
        .await
        else {
            return;
        };
        let ids: Vec<String> = value[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v["id"].as_str().map(str::to_string))
            .collect();
        if ids.is_empty() {
            return;
        }
        let permits = std::sync::Arc::new(Semaphore::new(SETUP_CONCURRENCY * 2));
        let mut set = tokio::task::JoinSet::new();
        for id in ids {
            let (client, url, token) = (
                client.clone(),
                format!("{host}{item}/{id}"),
                token.to_string(),
            );
            let permits = permits.clone();
            set.spawn(async move {
                let _permit = permits.acquire_owned().await.ok();
                matches!(
                    send_json(&client, reqwest::Method::DELETE, url, &token, None).await,
                    Some((status, _, _)) if status < 300 || status == 404
                )
            });
        }
        let mut deleted = 0usize;
        while let Some(res) = set.join_next().await {
            if matches!(res, Ok(true)) {
                deleted += 1;
            }
        }
        // Nothing could be deleted in this pass: stop instead of retrying.
        if deleted == 0 {
            return;
        }
    }
}

/// Delete everything the bootstrap and the run created (best effort).
pub async fn cleanup(host: &str, token: &str, bootstrap: &VuBootstrap) {
    let client = Client::new();
    // Deleting a user or a group that still has memberships fails with 409,
    // so remove the memberships the bootstrap created first.
    {
        let permits = std::sync::Arc::new(Semaphore::new(SETUP_CONCURRENCY * 2));
        let mut set = tokio::task::JoinSet::new();
        for seed in &bootstrap.seeds {
            for (group, user) in [
                (&seed.group_id, &seed.user_id),
                (&seed.scratch_group_id, &seed.scratch_user_id),
            ] {
                let (client, url, token) = (
                    client.clone(),
                    format!("{host}/v3/groups/{group}/users/{user}"),
                    token.to_string(),
                );
                let permits = permits.clone();
                set.spawn(async move {
                    let _permit = permits.acquire_owned().await.ok();
                    send_json(&client, reqwest::Method::DELETE, url, &token, None).await;
                });
            }
        }
        while set.join_next().await.is_some() {}
    }
    for domain in &bootstrap.domain_ids {
        for (list, key, item) in [
            ("projects", "projects", "projects"),
            ("groups", "groups", "groups"),
            ("users", "users", "users"),
        ] {
            delete_listed(
                &client,
                host,
                token,
                &format!("/v3/{list}?domain_id={domain}"),
                key,
                &format!("/v3/{item}"),
            )
            .await;
        }
        send_json(
            &client,
            reqwest::Method::PATCH,
            format!("{host}/v3/domains/{domain}"),
            token,
            Some(json!({"domain": {"enabled": false}})),
        )
        .await;
        send_json(
            &client,
            reqwest::Method::DELETE,
            format!("{host}/v3/domains/{domain}"),
            token,
            None,
        )
        .await;
    }
    let roles = CREATED_ROLES.lock().map(|r| r.clone()).unwrap_or_default();
    for id in roles {
        send_json(
            &client,
            reqwest::Method::DELETE,
            format!("{host}/v3/roles/{id}"),
            token,
            None,
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// Virtual user
// ---------------------------------------------------------------------------

fn password_body(user_name: &str, domain_id: &str, project_id: Option<&str>) -> Value {
    let mut auth = json!({"identity": {
        "methods": ["password"],
        "password": {"user": {
            "name": user_name,
            "domain": {"id": domain_id},
            "password": PASSWORD,
        }},
    }});
    if let Some(project_id) = project_id {
        auth["scope"] = json!({"project": {"id": project_id}});
    }
    json!({"auth": auth})
}

/// Result of one request.
struct Reply {
    status: u16,
    subject_token: Option<String>,
    body: Value,
}

/// Send one request. Statuses in `expected` are not counted as failures.
#[allow(clippy::too_many_arguments)]
async fn call(
    user: &mut GooseUser,
    method: GooseMethod,
    path: &str,
    name: &str,
    token: Option<&str>,
    subject: Option<&str>,
    body: Option<Value>,
    expected: &[u16],
) -> Result<Reply, Box<TransactionError>> {
    let mut req = user.get_request_builder(&method, path)?;
    if let Some(token) = token {
        req = req.header("x-auth-token", token);
    }
    if let Some(subject) = subject {
        req = req.header("x-subject-token", subject);
    }
    if let Some(body) = &body {
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
            user.set_failure(&format!("{name}: {e}"), &mut goose.request, None, None)?;
            return Ok(Reply {
                status: 0,
                subject_token: None,
                body: Value::Null,
            });
        }
    };
    let status = response.status().as_u16();
    let subject_token = response
        .headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if expected.contains(&status) {
        user.set_success(&mut goose.request)?;
    }
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok(Reply {
        status,
        subject_token,
        body,
    })
}

fn session(user: &GooseUser) -> VuSession {
    user.get_session_data_unchecked::<VuSession>().clone()
}

/// Forget a token the server rejected (revoked).
fn forget(user: &mut GooseUser, token: &str) {
    user.get_session_data_unchecked_mut::<VuSession>()
        .tokens
        .retain(|t| t != token);
    user.get_session_data_unchecked_mut::<VuSession>()
        .rescopable
        .retain(|t| t != token);
}

/// Keep the audit ids, issue time and origin of a freshly issued token.
fn note(user: &mut GooseUser, token: &str, origin: &str, body: &Value) {
    let t = &body["token"];
    let line = format!(
        "origin={origin} audit_ids={} issued_at={} project={}",
        t["audit_ids"], t["issued_at"], t["project"]["id"]
    );
    let s = user.get_session_data_unchecked_mut::<VuSession>();
    s.info.insert(token.to_string(), line);
    if s.info.len() > 4 * MAX_TOKENS {
        let keep: std::collections::HashSet<String> = s.tokens.iter().cloned().collect();
        s.info.retain(|k, _| keep.contains(k));
    }
}

/// Log the details of a token the server rejected (stderr, `load-*.log`).
fn trace_reject(user: &GooseUser, what: &str, status: u16, token: &str) {
    let s = user.get_session_data_unchecked::<VuSession>();
    let info = s.info.get(token).map_or("unknown", String::as_str);
    eprintln!(
        "VUREJECT now={} what={what} status={status} user={} {info}",
        chrono::Utc::now().to_rfc3339(),
        s.seed.user_name
    );
}

fn remember(user: &mut GooseUser, token: String) {
    let s = user.get_session_data_unchecked_mut::<VuSession>();
    s.tokens.push(token);
    if s.tokens.len() > MAX_TOKENS {
        s.tokens.remove(0);
    }
}

/// Remember a token that can be rescoped later (issued from a password).
fn remember_rescopable(user: &mut GooseUser, token: String) {
    let s = user.get_session_data_unchecked_mut::<VuSession>();
    s.rescopable.push(token.clone());
    if s.rescopable.len() > MAX_TOKENS {
        s.rescopable.remove(0);
    }
    remember(user, token);
}

/// `on_start`: pick a user of the bootstrap and log in as it.
pub async fn vu_start(user: &mut GooseUser) -> TransactionResult {
    let seeds = SEEDS.get().map_or(&[][..], Vec::as_slice);
    if seeds.is_empty() {
        return Ok(());
    }
    let seed = seeds[NEXT_SEED.fetch_add(1, Ordering::Relaxed) % seeds.len()].clone();
    user.set_session_data(VuSession {
        seed,
        tokens: Vec::new(),
        rescopable: Vec::new(),
        info: std::collections::HashMap::new(),
    });
    password_login(user).await
}

/// Password login, scoped to the first project.
async fn password_login(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let reply = call(
        user,
        GooseMethod::Post,
        "/v3/auth/tokens",
        "POST /v3/auth/tokens (password)",
        None,
        None,
        Some(password_body(
            &s.seed.user_name,
            &s.seed.domain_id,
            Some(&s.seed.project_ids[0]),
        )),
        &[],
    )
    .await?;
    if let (201, Some(token)) = (reply.status, reply.subject_token) {
        note(user, &token, "password", &reply.body);
        remember_rescopable(user, token);
    }
    Ok(())
}

/// Scope a password-issued token of the user to one of its projects.
async fn rescope(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let Some(token) = s.rescopable.last().cloned() else {
        return password_login(user).await;
    };
    let project = &s.seed.project_ids[usize::from(fastrand::bool())];
    let reply = call(
        user,
        GooseMethod::Post,
        "/v3/auth/tokens",
        "POST /v3/auth/tokens (rescope)",
        None,
        None,
        Some(json!({"auth": {
            "identity": {"methods": ["token"], "token": {"id": token}},
            "scope": {"project": {"id": project}},
        }})),
        &[],
    )
    .await?;
    match (reply.status, reply.subject_token) {
        (201, Some(new)) => {
            note(user, &new, "rescope", &reply.body);
            remember_rescopable(user, new)
        }
        (401, _) => {
            trace_reject(user, "rescope", 401, &token);
            forget(user, &token)
        }
        _ => {}
    }
    Ok(())
}

async fn app_cred_login(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let reply = call(
        user,
        GooseMethod::Post,
        "/v3/auth/tokens",
        "POST /v3/auth/tokens (application credential)",
        None,
        None,
        Some(json!({"auth": {"identity": {
            "methods": ["application_credential"],
            "application_credential": {
                "id": s.seed.app_cred_id,
                "secret": s.seed.app_cred_secret,
            },
        }}})),
        &[],
    )
    .await?;
    if let (201, Some(token)) = (reply.status, reply.subject_token) {
        note(user, &token, "app-cred", &reply.body);
        remember(user, token);
    }
    Ok(())
}

/// The admin validates one of the tokens of the user, without the catalog.
/// A revoked token (404/401) is dropped and the user logs in again.
async fn validate_token(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    if s.tokens.is_empty() {
        return password_login(user).await;
    }
    let index = fastrand::usize(..s.tokens.len());
    let token = s.tokens[index].clone();
    let reply = call(
        user,
        GooseMethod::Get,
        "/v3/auth/tokens?nocatalog=true",
        "GET /v3/auth/tokens?nocatalog=true (admin validates)",
        Some(admin_token()),
        Some(&token),
        None,
        &[],
    )
    .await?;
    if matches!(reply.status, 401 | 404) {
        trace_reject(user, "validate", reply.status, &token);
        forget(user, &token);
        if session(user).tokens.is_empty() {
            return password_login(user).await;
        }
    }
    Ok(())
}

async fn auth_projects(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let Some(token) = s.tokens.last() else {
        return password_login(user).await;
    };
    let reply = call(
        user,
        GooseMethod::Get,
        "/v3/auth/projects",
        "GET /v3/auth/projects",
        Some(token),
        None,
        None,
        &[],
    )
    .await?;
    if reply.status == 401 {
        forget(user, token);
    }
    Ok(())
}

async fn app_cred_list(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let Some(token) = s.tokens.last() else {
        return password_login(user).await;
    };
    let reply = call(
        user,
        GooseMethod::Get,
        &format!("/v3/users/{}/application_credentials", s.seed.user_id),
        "GET /v3/users/:id/application_credentials",
        Some(token),
        None,
        None,
        &[],
    )
    .await?;
    if reply.status == 401 {
        forget(user, token);
    }
    Ok(())
}

// --- revocation -----------------------------------------------------------

/// Issue a throw-away token from the user token and delete it.
async fn delete_token(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let Some(token) = s.tokens.last().cloned() else {
        return Ok(());
    };
    let reply = call(
        user,
        GooseMethod::Post,
        "/v3/auth/tokens",
        "POST /v3/auth/tokens (token to delete)",
        None,
        None,
        Some(json!({"auth": {"identity": {"methods": ["token"], "token": {"id": token}}}})),
        &[],
    )
    .await?;
    if reply.status == 401 {
        forget(user, &token);
    }
    if let (201, Some(victim)) = (reply.status, reply.subject_token) {
        call(
            user,
            GooseMethod::Delete,
            "/v3/auth/tokens",
            "DELETE /v3/auth/tokens",
            Some(admin_token()),
            Some(&victim),
            None,
            &[],
        )
        .await?;
    }
    Ok(())
}

/// Remove the role assignment of the scratch user and grant it again.
async fn revoke_role_assignment(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let path = format!(
        "/v3/projects/{}/users/{}/roles/{}",
        s.seed.scratch_project_id, s.seed.scratch_user_id, s.seed.role_id
    );
    call(
        user,
        GooseMethod::Delete,
        &path,
        "DELETE /v3/projects/:id/users/:id/roles/:id",
        Some(admin_token()),
        None,
        None,
        &[],
    )
    .await?;
    call(
        user,
        GooseMethod::Put,
        &path,
        "PUT /v3/projects/:id/users/:id/roles/:id",
        Some(admin_token()),
        None,
        None,
        &[],
    )
    .await?;
    Ok(())
}

/// Remove the scratch user from its group and add it again.
async fn remove_from_group(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let path = format!(
        "/v3/groups/{}/users/{}",
        s.seed.scratch_group_id, s.seed.scratch_user_id
    );
    call(
        user,
        GooseMethod::Delete,
        &path,
        "DELETE /v3/groups/:id/users/:id",
        Some(admin_token()),
        None,
        None,
        &[],
    )
    .await?;
    call(
        user,
        GooseMethod::Put,
        &path,
        "PUT /v3/groups/:id/users/:id",
        Some(admin_token()),
        None,
        None,
        &[],
    )
    .await?;
    Ok(())
}

async fn add_project(user: &mut GooseUser) -> Result<Option<String>, Box<TransactionError>> {
    let s = session(user);
    let reply = call(
        user,
        GooseMethod::Post,
        "/v3/projects",
        "POST /v3/projects",
        Some(admin_token()),
        None,
        Some(json!({"project": {
            "name": unique("vu-extra-project"),
            "domain_id": s.seed.domain_id,
            "enabled": true,
        }})),
        &[],
    )
    .await?;
    Ok(reply.body["project"]["id"].as_str().map(str::to_string))
}

async fn add_role(user: &mut GooseUser) -> Result<Option<String>, Box<TransactionError>> {
    let reply = call(
        user,
        GooseMethod::Post,
        "/v3/roles",
        "POST /v3/roles",
        Some(admin_token()),
        None,
        Some(json!({"role": {"name": unique("vu-role")}})),
        &[],
    )
    .await?;
    let id = reply.body["role"]["id"].as_str().map(str::to_string);
    if let Some(id) = &id
        && let Ok(mut roles) = CREATED_ROLES.lock()
    {
        roles.push(id.clone());
    }
    Ok(id)
}

async fn delete_project(user: &mut GooseUser) -> TransactionResult {
    if let Some(id) = add_project(user).await? {
        call(
            user,
            GooseMethod::Delete,
            &format!("/v3/projects/{id}"),
            "DELETE /v3/projects/:id",
            Some(admin_token()),
            None,
            None,
            &[],
        )
        .await?;
    }
    Ok(())
}

async fn delete_role(user: &mut GooseUser) -> TransactionResult {
    if let Some(id) = add_role(user).await? {
        call(
            user,
            GooseMethod::Delete,
            &format!("/v3/roles/{id}"),
            "DELETE /v3/roles/:id",
            Some(admin_token()),
            None,
            None,
            &[],
        )
        .await?;
    }
    Ok(())
}

/// Grant the role again: an assignment that already exists is replaced.
async fn upsert_role_assignment(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    call(
        user,
        GooseMethod::Put,
        &format!(
            "/v3/projects/{}/users/{}/roles/{}",
            s.seed.project_ids[0], s.seed.user_id, s.seed.role_id
        ),
        "PUT /v3/projects/:id/users/:id/roles/:id",
        Some(admin_token()),
        None,
        None,
        &[],
    )
    .await?;
    Ok(())
}

/// Check that the role assignment exists (`HEAD`).
async fn check_role_assignment(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    call(
        user,
        GooseMethod::Head,
        &format!(
            "/v3/projects/{}/users/{}/roles/{}",
            s.seed.project_ids[0], s.seed.user_id, s.seed.role_id
        ),
        "HEAD /v3/projects/:id/users/:id/roles/:id",
        Some(admin_token()),
        None,
        None,
        &[],
    )
    .await?;
    Ok(())
}

// --- administrative reads -------------------------------------------------

/// One `GET` of the admin on a path.
async fn admin_get(user: &mut GooseUser, path: &str, name: &str) -> TransactionResult {
    call(
        user,
        GooseMethod::Get,
        path,
        name,
        Some(admin_token()),
        None,
        None,
        &[],
    )
    .await?;
    Ok(())
}

/// What a Terraform refresh or a dashboard reads. Weights out of 12.
async fn admin_read(user: &mut GooseUser) -> TransactionResult {
    let s = session(user);
    let seed = &s.seed;
    match fastrand::u8(..12) {
        0 | 1 => {
            let project = &seed.project_ids[usize::from(fastrand::bool())];
            admin_get(
                user,
                &format!("/v3/projects/{project}"),
                "GET /v3/projects/:id",
            )
            .await
        }
        2 | 3 => {
            admin_get(
                user,
                &format!("/v3/users/{}", seed.user_id),
                "GET /v3/users/:id",
            )
            .await
        }
        4 => {
            admin_get(
                user,
                &format!("/v3/groups/{}", seed.group_id),
                "GET /v3/groups/:id",
            )
            .await
        }
        5 => {
            admin_get(
                user,
                &format!("/v3/roles/{}", seed.role_id),
                "GET /v3/roles/:id",
            )
            .await
        }
        6..=8 => {
            admin_get(
                user,
                &format!(
                    "/v3/role_assignments?user.id={}&scope.project.id={}",
                    seed.user_id, seed.project_ids[0]
                ),
                "GET /v3/role_assignments?user.id&scope.project.id",
            )
            .await
        }
        9 => {
            admin_get(
                user,
                &format!("/v3/role_assignments?user.id={}&effective=true", seed.user_id),
                "GET /v3/role_assignments?user.id&effective",
            )
            .await
        }
        10 => {
            admin_get(
                user,
                &format!("/v3/projects?domain_id={}", seed.domain_id),
                "GET /v3/projects?domain_id",
            )
            .await
        }
        _ => {
            admin_get(
                user,
                &format!("/v3/users?domain_id={}", seed.domain_id),
                "GET /v3/users?domain_id",
            )
            .await
        }
    }
}

/// Draw one operation.
pub async fn vu_op(user: &mut GooseUser) -> TransactionResult {
    if user.get_session_data::<VuSession>().is_none() {
        return Ok(());
    }
    // Cumulative bounds of the shares, in percent.
    let validate = pct("LOADTEST_VU_VALIDATE_PCT", 75.0);
    let admin_read_end = validate + pct("LOADTEST_VU_ADMIN_READ_PCT", 13.0);
    let hash_end = admin_read_end + pct("LOADTEST_VU_HASH_PCT", 3.0);
    let assign_end = hash_end + pct("LOADTEST_VU_ASSIGN_PCT", 2.0);
    let create_end = assign_end + pct("LOADTEST_VU_CREATE_PCT", 0.2);
    let revoke_end = create_end + pct("LOADTEST_VU_REVOKE_PCT", 0.02);
    let draw = fastrand::f64() * 100.0;
    if draw < validate {
        validate_token(user).await
    } else if draw < admin_read_end {
        admin_read(user).await
    } else if draw < hash_end {
        // Logins hash a password: password and application credential 2:1.
        if fastrand::u8(..3) < 2 {
            password_login(user).await
        } else {
            app_cred_login(user).await
        }
    } else if draw < assign_end {
        // Terraform grants roles that exist already far more often than it
        // looks them up.
        if fastrand::u8(..4) < 3 {
            upsert_role_assignment(user).await
        } else {
            check_role_assignment(user).await
        }
    } else if draw < create_end {
        if fastrand::bool() {
            add_project(user).await.map(|_| ())
        } else {
            add_role(user).await.map(|_| ())
        }
    } else if draw < revoke_end {
        let op = std::env::var("LOADTEST_VU_REVOKE_OP")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or_else(|| fastrand::u8(..5));
        match op {
            0 => delete_token(user).await,
            1 => revoke_role_assignment(user).await,
            2 => remove_from_group(user).await,
            3 => delete_project(user).await,
            _ => delete_role(user).await,
        }
    } else {
        // Weights 3:3:1 of the remaining share.
        match fastrand::u8(..7) {
            0..=2 => rescope(user).await,
            3..=5 => auth_projects(user).await,
            _ => app_cred_list(user).await,
        }
    }
}
