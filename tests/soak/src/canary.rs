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

//! Canaries: read-after-write and integrity checks on Raft-backed data.
//!
//! Every cycle the task writes one API key (a Raft-backed record, ADR 0021)
//! and one SCIM user (through the `/SCIM/v2` ingress, authenticated with an
//! API key bound to a SCIM realm, ADR 0024) through the cluster service and,
//! once the write is acknowledged, reads it from **every** node directly. A
//! node that does not return it serves a stale read (`read_after_write`). The
//! records written earlier are read back from every node each cycle and
//! compared with what was written, which catches data that was lost or altered
//! by restarts, snapshots or compaction (`integrity`). Transport errors, 429
//! and 5xx answers (a node that is being killed by chaos) are counted but not
//! judged. For SCIM reads a 401 is judged as well: the bearer key is valid,
//! so a node that rejects it has not applied the key yet.

use std::collections::VecDeque;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::server::Shared;

/// Failures kept for the report; older ones are dropped.
pub const MAX_FAILURES: usize = 200;
/// Written records that are still verified every cycle; older ones are
/// removed.
const TRACKED: usize = 20;
const DOMAIN: &str = "default";
const SCIM_IDP_NAME: &str = "soak-scim-idp";
const SCIM_REALM: &str = "soak-scim-realm";
const SCIM_ROLE: &str = "scim_provisioner";
const SCIM_MAPPING: &str = "soak-scim-mapping";
/// The SCIM bearer key lives one hour; mint a new one well before.
const SCIM_KEY_LIFETIME: Duration = Duration::from_secs(30 * 60);
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// Tells this run's records from those of earlier runs. The process id is
/// always 1 in a container, so the start time is part of it: records that a
/// previous pod left behind must not collide with new ones.
fn run_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        format!("{}-{secs}", std::process::id())
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct CanaryFailure {
    /// Monotonic number, stable when old records are dropped.
    pub seq: u64,
    pub at_secs: u64,
    /// `read_after_write` or `integrity`.
    pub check: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CanaryTotals {
    pub writes: u64,
    pub reads: u64,
    pub read_errors: u64,
    pub stale_reads: u64,
    pub mismatches: u64,
}

pub struct CanaryConfig {
    pub interval: Duration,
    /// Keystone API behind the cluster service.
    pub host: String,
    /// Port of the keystone API on every pod.
    pub api_port: u16,
    pub start: Instant,
    pub state: Shared,
    /// Headless service resolving to all pods.
    pub service: String,
}

/// A written record and what must read back.
struct Record {
    /// What the record is, for failure details.
    label: &'static str,
    id: String,
    /// Path (with query) that returns the record on any node.
    path: String,
    /// JSON pointer and the value expected there.
    expect: Vec<(&'static str, String)>,
    /// A 401 on read means the node has not applied the credential yet.
    unauthorized_is_stale: bool,
}

struct Api {
    http: reqwest::Client,
    host: String,
    token: Option<String>,
    /// Bearer key bound to the SCIM realm and when it was minted.
    scim_key: Option<(String, Instant)>,
}

impl Api {
    async fn login(&mut self) -> Result<()> {
        let var = |k: &str| std::env::var(k).with_context(|| format!("{k} is not set"));
        let body = json!({"auth": {
            "identity": {"methods": ["password"], "password": {"user": {
                "name": var("OS_USERNAME")?,
                "domain": {"id": var("OS_USER_DOMAIN_ID")?},
                "password": var("OS_PASSWORD")?,
            }}},
            "scope": {"project": {
                "name": var("OS_PROJECT_NAME")?,
                "domain": {"id": var("OS_PROJECT_DOMAIN_ID")?},
            }},
        }});
        let resp = self
            .http
            .post(format!("{}/v3/auth/tokens", self.host))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        let token = resp
            .headers()
            .get("x-subject-token")
            .and_then(|v| v.to_str().ok())
            .context("no X-Subject-Token in the login response")?;
        self.token = Some(token.to_string());
        Ok(())
    }

    async fn token(&mut self) -> Result<String> {
        if self.token.is_none() {
            self.login().await?;
        }
        self.token.clone().context("not logged in")
    }

    /// Send an admin request and log in again once if it was rejected.
    /// Returns the status and the JSON body (`null` when there is none).
    async fn send(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
        for attempt in 0..2 {
            let token = self.token().await?;
            let mut req = self
                .http
                .request(method.clone(), format!("{}{path}", self.host))
                .header("x-auth-token", token);
            if let Some(b) = body {
                req = req.json(b);
            }
            let resp = req.send().await?;
            let status = resp.status();
            if status == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.token = None;
                continue;
            }
            let val = resp.json().await.unwrap_or(Value::Null);
            return Ok((status, val));
        }
        bail!("authentication kept failing")
    }

    async fn expect(&mut self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let (status, val) = self.send(method, path, body).await?;
        if !status.is_success() {
            bail!("{path} answered {status}");
        }
        Ok(val)
    }

    async fn create_key(&mut self, provider_id: &str, description: &str) -> Result<Value> {
        let body = json!({"api_key": {
            "domain_id": DOMAIN,
            "provider_id": provider_id,
            "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            "description": description,
        }});
        self.expect(Method::POST, "/v4/api-keys", Some(&body)).await
    }

    async fn write_key(&mut self, n: u64) -> Result<Record> {
        let provider_id = format!("soak-canary-{}-{n}", run_id());
        let description = format!("soak canary {n} {provider_id}");
        let val = self.create_key(&provider_id, &description).await?;
        let client_id = val["api_key"]["client_id"]
            .as_str()
            .context("create answered without a client_id")?
            .to_owned();
        Ok(Record {
            label: "key",
            path: format!("/v4/api-keys/{client_id}?domain_id={DOMAIN}"),
            expect: vec![
                ("/api_key/client_id", client_id.clone()),
                ("/api_key/provider_id", provider_id),
                ("/api_key/description", description),
            ],
            id: client_id,
            unauthorized_is_stale: false,
        })
    }

    async fn revoke_key(&mut self, client_id: &str) {
        let path = format!("/v4/api-keys/{client_id}/revoke?domain_id={DOMAIN}");
        let _ = self.send(Method::POST, &path, None).await;
    }

    /// Create the IdP and the realm if needed and mint a key bound to it.
    async fn mint_scim_key(&mut self) -> Result<String> {
        let idp = json!({"identity_provider": {"name": SCIM_IDP_NAME, "domain_id": DOMAIN}});
        let (status, val) = self
            .send(
                Method::POST,
                "/v4/federation/identity_providers",
                Some(&idp),
            )
            .await?;
        let idp_id = if status == StatusCode::CONFLICT {
            let list = self
                .expect(
                    Method::GET,
                    &format!("/v4/federation/identity_providers?domain_id={DOMAIN}"),
                    None,
                )
                .await?;
            list["identity_providers"]
                .as_array()
                .and_then(|a| a.iter().find(|i| i["name"] == SCIM_IDP_NAME))
                .and_then(|i| i["id"].as_str())
                .context("the SCIM identity provider exists but is not listed")?
                .to_owned()
        } else if status.is_success() {
            val["identity_provider"]["id"]
                .as_str()
                .context("identity provider answered without an id")?
                .to_owned()
        } else {
            bail!("creating the identity provider answered {status}");
        };

        let realm = json!({"scim_realm": {
            "domain_id": DOMAIN,
            "provider_id": SCIM_REALM,
            "idp_id": idp_id,
            "display_name": "Soak SCIM realm",
        }});
        let (status, _) = self
            .send(Method::POST, "/v4/scim_realms", Some(&realm))
            .await?;
        if !status.is_success() && status != StatusCode::CONFLICT {
            bail!("creating the SCIM realm answered {status}");
        }

        self.ensure_scim_access().await?;

        let val = self
            .create_key(SCIM_REALM, "soak canary SCIM connector")
            .await?;
        val["token"]
            .as_str()
            .map(str::to_owned)
            .context("API key answered without a token")
    }

    /// Id of the role `name`, created if it does not exist.
    async fn ensure_role(&mut self, name: &str) -> Result<String> {
        let (status, val) = self
            .send(
                Method::POST,
                "/v3/roles",
                Some(&json!({"role": {"name": name}})),
            )
            .await?;
        if status.is_success() {
            return val["role"]["id"]
                .as_str()
                .map(str::to_owned)
                .context("role answered without an id");
        }
        let list = self
            .expect(Method::GET, &format!("/v3/roles?name={name}"), None)
            .await?;
        list["roles"]
            .as_array()
            .and_then(|a| a.iter().find(|r| r["name"] == name))
            .and_then(|r| r["id"].as_str())
            .map(str::to_owned)
            .with_context(|| format!("role {name} does not exist (create answered {status})"))
    }

    /// Grant the realm's API clients the `scim_provisioner` role on the
    /// domain, as `/SCIM/v2` requires an `ApiClient` mapping ruleset (ADR
    /// 0021 and 0024). Safe to repeat.
    async fn ensure_scim_access(&mut self) -> Result<()> {
        let role_id = self.ensure_role(SCIM_ROLE).await?;
        let manager_id = self.ensure_role("manager").await?;
        // The rule outlives the soak pod and creating it twice is a conflict,
        // so only create it when it is missing.
        let imply = format!("/v3/roles/{role_id}/implies/{manager_id}");
        let (status, _) = self.send(Method::GET, &imply, None).await?;
        if status == StatusCode::NOT_FOUND {
            self.expect(Method::PUT, &imply, None).await?;
        } else if !status.is_success() {
            bail!("{imply} answered {status}");
        }

        let ruleset = json!({"mapping": {
            "mapping_id": SCIM_MAPPING,
            "domain_id": DOMAIN,
            "source": {"type": "api_client", "provider_id": SCIM_REALM},
            "domain_resolution_mode": {"type": "fixed"},
            "enabled": true,
            "rules": [{
                "name": "soak-scim-rule",
                "match": {"all_of": []},
                "identity": {"user_name": "${claims.api_client.client_id}"},
                "groups": [],
                "authorizations": [{
                    "type": "domain",
                    "domain_id": DOMAIN,
                    "roles": [{"id": role_id, "name": SCIM_ROLE}],
                }],
            }],
        }});
        let (status, _) = self
            .send(Method::POST, "/v4/mappings/rulesets", Some(&ruleset))
            .await?;
        if !status.is_success() && status != StatusCode::CONFLICT {
            bail!("creating the SCIM mapping ruleset answered {status}");
        }
        Ok(())
    }

    /// Bearer key for `/SCIM/v2`, minted again once it gets old.
    async fn scim_bearer(&mut self) -> Result<String> {
        if let Some((key, at)) = &self.scim_key
            && at.elapsed() < SCIM_KEY_LIFETIME
        {
            return Ok(key.clone());
        }
        let key = self.mint_scim_key().await?;
        self.scim_key = Some((key.clone(), Instant::now()));
        Ok(key)
    }

    async fn write_scim_user(&mut self, bearer: &str, n: u64) -> Result<Record> {
        let user_name = format!("soak-canary-{}-{n}", run_id());
        let external_id = format!("soak-ext-{}-{n}", run_id());
        let body = json!({
            "schemas": [USER_SCHEMA],
            "externalId": external_id,
            "userName": user_name,
            "name": {"givenName": "Soak", "familyName": "Canary"},
            "emails": [{"value": format!("{user_name}@example.org"), "primary": true}],
            "active": true,
        });
        let resp = self
            .http
            .post(format!("{}/SCIM/v2/{DOMAIN}/Users", self.host))
            .bearer_auth(bearer)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            bail!("creating the SCIM user answered {status}");
        }
        let val: Value = resp.json().await?;
        let id = val["id"]
            .as_str()
            .context("SCIM create answered without an id")?
            .to_owned();
        Ok(Record {
            label: "SCIM user",
            path: format!("/SCIM/v2/{DOMAIN}/Users/{id}"),
            expect: vec![
                ("/id", id.clone()),
                ("/userName", user_name),
                ("/externalId", external_id),
            ],
            id,
            unauthorized_is_stale: true,
        })
    }

    async fn delete_scim_user(&self, bearer: &str, id: &str) {
        let _ = self
            .http
            .delete(format!("{}/SCIM/v2/{DOMAIN}/Users/{id}", self.host))
            .bearer_auth(bearer)
            .send()
            .await;
    }
}

/// Result of a write sent straight to one node.
#[derive(Debug, PartialEq)]
pub enum ProbeWrite {
    /// The node acknowledged the write.
    Accepted,
    /// The node refused, failed or did not answer in time.
    Rejected(String),
    /// The node could not authenticate the request, nothing is known.
    Inconclusive,
}

/// Classify the answer to a probe write.
fn classify_probe(status: Option<StatusCode>, error: &str) -> ProbeWrite {
    match status {
        Some(s) if s.is_success() => ProbeWrite::Accepted,
        Some(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => ProbeWrite::Inconclusive,
        Some(s) => ProbeWrite::Rejected(format!("answered {s}")),
        None => ProbeWrite::Rejected(error.to_string()),
    }
}

/// Logs in through the cluster service and writes one API key to a given
/// node, to see whether that node can commit.
pub struct Prober {
    api: Api,
    n: u64,
}

impl Prober {
    pub fn new(host: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            api: Api {
                http,
                host: host.trim_end_matches('/').to_string(),
                token: None,
                scim_key: None,
            },
            n: 0,
        })
    }

    /// Get a token now so it exists when a node is cut off.
    pub async fn login(&mut self) -> Result<()> {
        self.api.token().await.map(|_| ())
    }

    /// Write one API key through `node` (`host:port`).
    pub async fn write_via(&mut self, node: &str) -> ProbeWrite {
        self.n += 1;
        let provider_id = format!("soak-probe-{}-{}", run_id(), self.n);
        let token = match self.api.token().await {
            Ok(t) => t,
            Err(e) => return ProbeWrite::Rejected(format!("login failed: {e:#}")),
        };
        let body = json!({"api_key": {
            "domain_id": DOMAIN,
            "provider_id": provider_id,
            "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            "description": "soak partition probe",
        }});
        let sent = self
            .api
            .http
            .post(format!("http://{node}/v4/api-keys"))
            .header("x-auth-token", token)
            .json(&body)
            .send()
            .await;
        match sent {
            Ok(r) => {
                let status = r.status();
                if status == StatusCode::UNAUTHORIZED {
                    self.api.token = None;
                }
                classify_probe(Some(status), "")
            }
            Err(e) => classify_probe(None, &e.to_string()),
        }
    }
}

/// Pod IPs behind the headless service.
async fn node_ips(service: &str) -> Vec<String> {
    match tokio::net::lookup_host((service, 0)).await {
        Ok(addrs) => {
            let mut v: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            v.sort();
            v.dedup();
            v
        }
        Err(e) => {
            warn!(%service, error = %e, "canary cannot resolve the nodes");
            Vec::new()
        }
    }
}

/// Outcome of reading one record from one node.
#[derive(Debug, PartialEq)]
enum Read {
    Ok,
    /// Not judged: the node could not answer.
    Unavailable,
    Missing,
    Altered(String),
}

fn judge(status: Option<StatusCode>, body: &Value, rec: &Record) -> Read {
    let Some(status) = status else {
        return Read::Unavailable;
    };
    if status == StatusCode::NOT_FOUND
        || (rec.unauthorized_is_stale && status == StatusCode::UNAUTHORIZED)
    {
        return Read::Missing;
    }
    if !status.is_success() {
        return Read::Unavailable;
    }
    for (pointer, want) in &rec.expect {
        let got = body.pointer(pointer);
        if got.and_then(Value::as_str) != Some(want.as_str()) {
            let got = got.map_or_else(|| "missing".to_string(), Value::to_string);
            return Read::Altered(format!("{pointer} is {got} instead of {want:?}"));
        }
    }
    Read::Ok
}

async fn read_from(
    http: &reqwest::Client,
    node: &str,
    headers: &[(&str, String)],
    rec: &Record,
) -> Read {
    let mut req = http.get(format!("http://{node}{}", rec.path));
    for (name, value) in headers {
        req = req.header(*name, value);
    }
    let Ok(resp) = req.send().await else {
        return Read::Unavailable;
    };
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    judge(Some(status), &body, rec)
}

fn record_failure(cfg: &CanaryConfig, seq: &mut u64, check: &'static str, detail: String) {
    *seq += 1;
    warn!(check, %detail, "canary failed");
    if let Ok(mut g) = cfg.state.write() {
        match check {
            "read_after_write" => g.canary.totals.stale_reads += 1,
            _ => g.canary.totals.mismatches += 1,
        }
        g.canary.failures.push(CanaryFailure {
            seq: *seq,
            at_secs: cfg.start.elapsed().as_secs(),
            check,
            detail,
        });
        let extra = g.canary.failures.len().saturating_sub(MAX_FAILURES);
        g.canary.failures.drain(..extra);
    }
}

/// Read `rec` from every node and record what is wrong.
async fn verify(
    cfg: &CanaryConfig,
    http: &reqwest::Client,
    headers: &[(&str, String)],
    nodes: &[String],
    rec: &Record,
    check_on_missing: &'static str,
    seq: &mut u64,
) {
    for node in nodes {
        let addr = format!("{node}:{}", cfg.api_port);
        let r = read_from(http, &addr, headers, rec).await;
        if let Ok(mut g) = cfg.state.write() {
            match r {
                Read::Unavailable => g.canary.totals.read_errors += 1,
                _ => g.canary.totals.reads += 1,
            }
        }
        match r {
            Read::Ok | Read::Unavailable => {}
            Read::Missing => record_failure(
                cfg,
                seq,
                check_on_missing,
                format!("{addr} does not return {} {}", rec.label, rec.id),
            ),
            Read::Altered(d) => record_failure(
                cfg,
                seq,
                "integrity",
                format!("{addr} returns {} {} altered: {d}", rec.label, rec.id),
            ),
        }
    }
}

/// Verify a new record on every node, then everything written before it.
async fn verify_cycle(
    cfg: &CanaryConfig,
    http: &reqwest::Client,
    headers: &[(&str, String)],
    tracked: &mut VecDeque<Record>,
    rec: Record,
    seq: &mut u64,
) {
    let nodes = node_ips(&cfg.service).await;
    verify(cfg, http, headers, &nodes, &rec, "read_after_write", seq).await;
    tracked.push_back(rec);
    // Everything written earlier must still read back unchanged.
    for old in tracked.iter().take(tracked.len().saturating_sub(1)) {
        verify(cfg, http, headers, &nodes, old, "integrity", seq).await;
    }
}

pub async fn run(cfg: CanaryConfig, deadline: Option<Instant>) -> Result<()> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let mut api = Api {
        http: http.clone(),
        host: cfg.host.trim_end_matches('/').to_string(),
        token: None,
        scim_key: None,
    };
    info!(interval = ?cfg.interval, "canary enabled");
    let mut keys: VecDeque<Record> = VecDeque::new();
    let mut users: VecDeque<Record> = VecDeque::new();
    let mut seq = 0u64;
    let mut n = 0u64;
    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(());
        }
        n += 1;

        // Writes fail while the leader is being replaced.
        match api.write_key(n).await {
            Ok(rec) => {
                if let Ok(mut g) = cfg.state.write() {
                    g.canary.totals.writes += 1;
                }
                if let Ok(token) = api.token().await {
                    let headers = [("x-auth-token", token)];
                    verify_cycle(&cfg, &http, &headers, &mut keys, rec, &mut seq).await;
                }
            }
            Err(e) => warn!(error = %format!("{e:#}"), "canary key write failed"),
        }
        while keys.len() > TRACKED {
            if let Some(old) = keys.pop_front() {
                api.revoke_key(&old.id).await;
            }
        }

        let bearer = match api.scim_bearer().await {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "canary SCIM setup failed");
                continue;
            }
        };
        match api.write_scim_user(&bearer, n).await {
            Ok(rec) => {
                if let Ok(mut g) = cfg.state.write() {
                    g.canary.totals.writes += 1;
                }
                let headers = [("authorization", format!("Bearer {bearer}"))];
                verify_cycle(&cfg, &http, &headers, &mut users, rec, &mut seq).await;
            }
            Err(e) => warn!(error = %format!("{e:#}"), "canary SCIM user write failed"),
        }
        while users.len() > TRACKED {
            if let Some(old) = users.pop_front() {
                api.delete_scim_user(&bearer, &old.id).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(unauthorized_is_stale: bool) -> Record {
        Record {
            label: "key",
            id: "c1".into(),
            path: "/x".into(),
            expect: vec![
                ("/api_key/client_id", "c1".into()),
                ("/api_key/provider_id", "p1".into()),
            ],
            unauthorized_is_stale,
        }
    }

    fn body(provider: &str) -> Value {
        json!({"api_key": {"client_id": "c1", "provider_id": provider}})
    }

    #[test]
    fn judges_reads() {
        let r = rec(false);
        assert_eq!(judge(Some(StatusCode::OK), &body("p1"), &r), Read::Ok);
        assert_eq!(judge(None, &Value::Null, &r), Read::Unavailable);
        assert_eq!(
            judge(Some(StatusCode::SERVICE_UNAVAILABLE), &Value::Null, &r),
            Read::Unavailable
        );
        assert_eq!(
            judge(Some(StatusCode::NOT_FOUND), &Value::Null, &r),
            Read::Missing
        );
        assert!(matches!(
            judge(Some(StatusCode::OK), &body("other"), &r),
            Read::Altered(_)
        ));
        assert!(matches!(
            judge(Some(StatusCode::OK), &Value::Null, &r),
            Read::Altered(_)
        ));
    }

    #[test]
    fn classifies_probe_writes() {
        assert_eq!(
            classify_probe(Some(StatusCode::CREATED), ""),
            ProbeWrite::Accepted
        );
        assert_eq!(
            classify_probe(Some(StatusCode::UNAUTHORIZED), ""),
            ProbeWrite::Inconclusive
        );
        assert!(matches!(
            classify_probe(Some(StatusCode::SERVICE_UNAVAILABLE), ""),
            ProbeWrite::Rejected(_)
        ));
        assert!(matches!(
            classify_probe(None, "timed out"),
            ProbeWrite::Rejected(_)
        ));
    }

    #[test]
    fn judges_unauthorized_by_record() {
        assert_eq!(
            judge(Some(StatusCode::UNAUTHORIZED), &Value::Null, &rec(true)),
            Read::Missing
        );
        assert_eq!(
            judge(Some(StatusCode::UNAUTHORIZED), &Value::Null, &rec(false)),
            Read::Unavailable
        );
        assert_eq!(
            judge(
                Some(StatusCode::TOO_MANY_REQUESTS),
                &Value::Null,
                &rec(true)
            ),
            Read::Unavailable
        );
    }
}
