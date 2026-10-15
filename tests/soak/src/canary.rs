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
//! through the cluster service and, once the write is acknowledged, reads it
//! from **every** node directly. A node that does not return it serves a
//! stale read (`read_after_write`). The keys written earlier are read back
//! from every node each cycle and compared with what was written, which
//! catches data that was lost or altered by restarts, snapshots or
//! compaction (`integrity`). Transport errors and 5xx answers (a node that
//! is being killed by chaos) are counted but not judged.

use std::collections::VecDeque;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::server::Shared;

/// Failures kept for the report; older ones are dropped.
pub const MAX_FAILURES: usize = 200;
/// Written keys that are still verified every cycle; older ones are revoked.
const TRACKED: usize = 20;
const DOMAIN: &str = "default";

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
    client_id: String,
    provider_id: String,
    description: String,
}

struct Api {
    http: reqwest::Client,
    host: String,
    token: Option<String>,
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

    /// Run `f` with a token and log in again once if it was rejected.
    async fn authed<T>(
        &mut self,
        f: impl Fn(String) -> std::pin::Pin<Box<dyn Future<Output = Result<(StatusCode, T)>> + Send>>,
    ) -> Result<T> {
        for attempt in 0..2 {
            let token = self.token().await?;
            let (status, out) = f(token).await?;
            if status == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.token = None;
                continue;
            }
            if !status.is_success() {
                bail!("unexpected status {status}");
            }
            return Ok(out);
        }
        bail!("authentication kept failing")
    }

    async fn create(&mut self, provider_id: &str, description: &str) -> Result<String> {
        let (http, host) = (self.http.clone(), self.host.clone());
        let body = json!({"api_key": {
            "domain_id": DOMAIN,
            "provider_id": provider_id,
            "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            "description": description,
        }});
        let val: Value = self
            .authed(|token| {
                let (http, host, body) = (http.clone(), host.clone(), body.clone());
                Box::pin(async move {
                    let r = http
                        .post(format!("{host}/v4/api-keys"))
                        .header("x-auth-token", token)
                        .json(&body)
                        .send()
                        .await?;
                    let status = r.status();
                    let val = if status.is_success() {
                        r.json().await?
                    } else {
                        Value::Null
                    };
                    Ok((status, val))
                })
            })
            .await?;
        val["api_key"]["client_id"]
            .as_str()
            .map(str::to_owned)
            .context("create answered without a client_id")
    }

    async fn revoke(&mut self, client_id: &str) {
        let (http, host) = (self.http.clone(), self.host.clone());
        let path = format!("{host}/v4/api-keys/{client_id}/revoke?domain_id={DOMAIN}");
        let _ = self
            .authed(|token| {
                let (http, path) = (http.clone(), path.clone());
                Box::pin(async move {
                    let r = http.post(path).header("x-auth-token", token).send().await?;
                    Ok((r.status(), ()))
                })
            })
            .await;
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
    if status == StatusCode::NOT_FOUND {
        return Read::Missing;
    }
    if !status.is_success() {
        return Read::Unavailable;
    }
    let key = &body["api_key"];
    for (field, want) in [
        ("client_id", &rec.client_id),
        ("provider_id", &rec.provider_id),
        ("description", &rec.description),
    ] {
        if key[field].as_str() != Some(want.as_str()) {
            return Read::Altered(format!("{field} is {} instead of {want:?}", key[field]));
        }
    }
    Read::Ok
}

async fn read_from(http: &reqwest::Client, node: &str, token: &str, rec: &Record) -> Read {
    let url = format!(
        "http://{node}/v4/api-keys/{}?domain_id={DOMAIN}",
        rec.client_id
    );
    let Ok(resp) = http.get(url).header("x-auth-token", token).send().await else {
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
    token: &str,
    nodes: &[String],
    rec: &Record,
    check_on_missing: &'static str,
    seq: &mut u64,
) {
    for node in nodes {
        let addr = format!("{node}:{}", cfg.api_port);
        let r = read_from(http, &addr, token, rec).await;
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
                format!("{addr} does not return key {}", rec.client_id),
            ),
            Read::Altered(d) => record_failure(
                cfg,
                seq,
                "integrity",
                format!("{addr} returns key {} altered: {d}", rec.client_id),
            ),
        }
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
    };
    info!(interval = ?cfg.interval, "canary enabled");
    let mut tracked: VecDeque<Record> = VecDeque::new();
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
        let provider_id = format!("soak-canary-{}-{n}", std::process::id());
        let description = format!("soak canary {n} {provider_id}");
        let client_id = match api.create(&provider_id, &description).await {
            Ok(id) => id,
            Err(e) => {
                // Writes fail while the leader is being replaced.
                warn!(error = %format!("{e:#}"), "canary write failed");
                continue;
            }
        };
        if let Ok(mut g) = cfg.state.write() {
            g.canary.totals.writes += 1;
        }
        let rec = Record {
            client_id,
            provider_id,
            description,
        };
        let Ok(token) = api.token().await else {
            continue;
        };
        let nodes = node_ips(&cfg.service).await;
        verify(
            &cfg,
            &http,
            &token,
            &nodes,
            &rec,
            "read_after_write",
            &mut seq,
        )
        .await;
        tracked.push_back(rec);

        // Everything written earlier must still read back unchanged.
        for old in tracked.iter().take(tracked.len().saturating_sub(1)) {
            verify(&cfg, &http, &token, &nodes, old, "integrity", &mut seq).await;
        }
        while tracked.len() > TRACKED {
            if let Some(old) = tracked.pop_front() {
                api.revoke(&old.client_id).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> Record {
        Record {
            client_id: "c1".into(),
            provider_id: "p1".into(),
            description: "d1".into(),
        }
    }

    fn body(provider: &str) -> Value {
        json!({"api_key": {"client_id": "c1", "provider_id": provider, "description": "d1"}})
    }

    #[test]
    fn judges_reads() {
        let r = rec();
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
    }
}
