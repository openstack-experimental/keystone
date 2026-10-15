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

//! Chaos: periodically delete one Raft pod while the load keeps running.
//!
//! The pods are deleted one after another in name order, so every node,
//! including whichever one currently leads, is hit repeatedly over a long
//! run. A pod is only killed while all pods are ready, and the next one only
//! after the previous victim came back (new pod, ready again). A victim that
//! is not back within the recovery timeout is an invariant violation, see
//! `check_chaos` in `main.rs`. Request failures caused by the kills are
//! judged by the load error-rate invariant.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::server::Shared;

/// Events kept for the report; older ones are dropped (the totals still
/// cover them).
pub const MAX_EVENTS: usize = 500;
const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
pub(crate) const POLL: Duration = Duration::from_secs(5);

/// One pod kill and what became of it.
#[derive(Clone, Debug, Serialize)]
pub struct ChaosEvent {
    /// Monotonic number, stable when old records are dropped.
    pub seq: u64,
    pub pod: String,
    pub at_secs: u64,
    /// Seconds until the replacement pod was ready; `None` while waiting or
    /// when it never came back.
    pub recovery_secs: Option<u64>,
    pub timed_out: bool,
}

/// Counters over the whole run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ChaosTotals {
    pub kills: u64,
    pub recovered: u64,
    pub timed_out: u64,
    pub last_recovery_secs: u64,
    pub max_recovery_secs: u64,
}

pub struct ChaosConfig {
    pub interval: Duration,
    pub recovery_timeout: Duration,
    /// Label selector of the Raft pods.
    pub selector: String,
    pub expected_pods: usize,
    pub start: Instant,
    pub state: Shared,
}

#[derive(Debug, Deserialize)]
struct PodList {
    items: Vec<Pod>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Pod {
    pub(crate) metadata: Meta,
    #[serde(default)]
    status: Status,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Meta {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) uid: String,
    #[serde(default, rename = "deletionTimestamp")]
    deletion_timestamp: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Status {
    #[serde(default)]
    conditions: Vec<Condition>,
    #[serde(default, rename = "containerStatuses")]
    container_statuses: Vec<ContainerStatus>,
}

#[derive(Debug, Deserialize)]
struct ContainerStatus {
    #[serde(default, rename = "restartCount")]
    restart_count: u64,
}

#[derive(Debug, Deserialize)]
struct Condition {
    #[serde(rename = "type")]
    kind: String,
    status: String,
}

impl Pod {
    /// Container restarts of this pod so far.
    pub(crate) fn restarts(&self) -> u64 {
        self.status
            .container_statuses
            .iter()
            .map(|c| c.restart_count)
            .sum()
    }

    pub(crate) fn ready(&self) -> bool {
        self.metadata.deletion_timestamp.is_none()
            && self
                .status
                .conditions
                .iter()
                .any(|c| c.kind == "Ready" && c.status == "True")
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct StatefulSet {
    metadata: StatefulSetMeta,
    #[serde(default)]
    spec: StatefulSetSpec,
    #[serde(default)]
    status: StatefulSetStatus,
}

#[derive(Debug, Deserialize)]
struct StatefulSetMeta {
    #[serde(default)]
    generation: i64,
}

#[derive(Debug, Default, Deserialize)]
struct StatefulSetSpec {
    #[serde(default)]
    replicas: i64,
}

#[derive(Debug, Default, Deserialize)]
struct StatefulSetStatus {
    #[serde(default, rename = "observedGeneration")]
    observed_generation: i64,
    #[serde(default, rename = "readyReplicas")]
    ready_replicas: i64,
    #[serde(default, rename = "updatedReplicas")]
    updated_replicas: i64,
    #[serde(default, rename = "currentRevision")]
    current_revision: String,
    #[serde(default, rename = "updateRevision")]
    update_revision: String,
}

impl StatefulSet {
    /// Every pod runs the latest revision and is ready.
    pub(crate) fn rolled_out(&self) -> bool {
        let (st, want) = (&self.status, self.spec.replicas);
        st.observed_generation >= self.metadata.generation
            && st.updated_replicas == want
            && st.ready_replicas == want
            && st.current_revision == st.update_revision
    }
}

/// Minimal in-cluster Kubernetes client: list and delete pods.
pub(crate) struct Kube {
    http: reqwest::Client,
    base: String,
    namespace: String,
}

impl Kube {
    pub(crate) async fn in_cluster() -> Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .context("KUBERNETES_SERVICE_HOST is not set, not running in a cluster")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let ca = tokio::fs::read(format!("{SERVICE_ACCOUNT}/ca.crt"))
            .await
            .context("cannot read the cluster CA")?;
        let namespace = tokio::fs::read_to_string(format!("{SERVICE_ACCOUNT}/namespace"))
            .await
            .context("cannot read the namespace")?;
        let http = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .timeout(Duration::from_secs(10))
            .build()?;
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        Ok(Self {
            http,
            base: format!("https://{host}:{port}"),
            namespace: namespace.trim().to_string(),
        })
    }

    /// The projected token rotates, so read it for every call.
    async fn token(&self) -> Result<String> {
        let token = tokio::fs::read_to_string(format!("{SERVICE_ACCOUNT}/token"))
            .await
            .context("cannot read the service account token")?;
        Ok(token.trim().to_string())
    }

    pub(crate) async fn pods(&self, selector: &str) -> Result<Vec<Pod>> {
        self.pods_in(&self.namespace, selector).await
    }

    /// Pods matching `selector` in another namespace.
    pub(crate) async fn pods_in(&self, namespace: &str, selector: &str) -> Result<Vec<Pod>> {
        let list: PodList = self
            .http
            .get(format!("{}/api/v1/namespaces/{namespace}/pods", self.base))
            .query(&[("labelSelector", selector)])
            .bearer_auth(self.token().await?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut pods = list.items;
        pods.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
        Ok(pods)
    }

    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Call the Kubernetes API with a JSON body and return the JSON answer
    /// (`null` when there is none). `PATCH` sends a merge patch.
    pub(crate) async fn json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let patch = method == reqwest::Method::PATCH;
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(self.token().await?);
        if let Some(b) = body {
            req = req
                .header(
                    "content-type",
                    if patch {
                        "application/merge-patch+json"
                    } else {
                        "application/json"
                    },
                )
                .body(b.to_string());
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            let short: String = text.chars().take(200).collect();
            anyhow::bail!("{path} answered {status}: {short}");
        }
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
    }

    /// GET a plain-text answer such as a pod log.
    pub(crate) async fn text(&self, path: &str) -> Result<String> {
        Ok(self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(self.token().await?)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?)
    }

    fn statefulset_url(&self, name: &str) -> String {
        format!(
            "{}/apis/apps/v1/namespaces/{}/statefulsets/{name}",
            self.base, self.namespace
        )
    }

    pub(crate) async fn statefulset(&self, name: &str) -> Result<StatefulSet> {
        Ok(self
            .http
            .get(self.statefulset_url(name))
            .bearer_auth(self.token().await?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Roll the pods of a StatefulSet the way `kubectl rollout restart` does.
    pub(crate) async fn restart_statefulset(&self, name: &str, at: &str) -> Result<()> {
        let patch = serde_json::json!({"spec": {"template": {"metadata": {"annotations": {
            "kubectl.kubernetes.io/restartedAt": at,
        }}}}});
        self.http
            .patch(self.statefulset_url(name))
            .bearer_auth(self.token().await?)
            .header("content-type", "application/strategic-merge-patch+json")
            .body(patch.to_string())
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn policies_url(&self) -> String {
        format!(
            "{}/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies",
            self.base, self.namespace
        )
    }

    pub(crate) async fn create_policy(&self, policy: &serde_json::Value) -> Result<()> {
        self.http
            .post(self.policies_url())
            .bearer_auth(self.token().await?)
            .json(policy)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub(crate) async fn delete_policy(&self, name: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!("{}/{name}", self.policies_url()))
            .bearer_auth(self.token().await?)
            .send()
            .await?;
        // Already gone is fine.
        if resp.status() != reqwest::StatusCode::NOT_FOUND {
            resp.error_for_status()?;
        }
        Ok(())
    }

    /// Delete every policy carrying `selector`, e.g. left by a crashed run.
    pub(crate) async fn delete_policies(&self, selector: &str) -> Result<()> {
        self.http
            .delete(self.policies_url())
            .query(&[("labelSelector", selector)])
            .bearer_auth(self.token().await?)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub(crate) async fn delete(&self, name: &str) -> Result<()> {
        self.delete_in(&self.namespace, name).await
    }

    /// Delete a pod of another namespace.
    pub(crate) async fn delete_in(&self, namespace: &str, name: &str) -> Result<()> {
        self.http
            .delete(format!(
                "{}/api/v1/namespaces/{namespace}/pods/{name}",
                self.base
            ))
            .bearer_auth(self.token().await?)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// Next victim: the pod after `previous` in name order, wrapping around.
fn pick_victim<'a>(pods: &'a [Pod], previous: Option<&str>) -> Option<&'a Pod> {
    let after = previous.and_then(|p| pods.iter().position(|x| x.metadata.name == p));
    let idx = after.map_or(0, |i| (i + 1) % pods.len().max(1));
    pods.get(idx)
}

pub(crate) fn all_ready(pods: &[Pod], expected: usize) -> bool {
    pods.len() >= expected && pods.iter().all(Pod::ready)
}

/// Sleep for `d`; `false` when the deadline passes first.
pub(crate) async fn sleep_until_deadline(d: Duration, deadline: Option<Instant>) -> bool {
    match deadline {
        Some(dl) if Instant::now() + d >= dl => false,
        _ => {
            tokio::time::sleep(d).await;
            true
        }
    }
}

fn update_event(cfg: &ChaosConfig, seq: u64, f: impl FnOnce(&mut ChaosEvent)) {
    if let Ok(mut g) = cfg.state.write()
        && let Some(e) = g.chaos.events.iter_mut().find(|e| e.seq == seq)
    {
        f(e);
    }
}

pub async fn run(cfg: ChaosConfig, deadline: Option<Instant>) -> Result<()> {
    let kube = Kube::in_cluster().await?;
    info!(interval = ?cfg.interval, recovery = ?cfg.recovery_timeout, "chaos enabled");
    let mut previous: Option<String> = None;
    let mut seq = 0u64;
    loop {
        if !sleep_until_deadline(cfg.interval, deadline).await {
            return Ok(());
        }

        // Only break a healthy cluster, never one that is still recovering
        // or has a node cut off by the partition task.
        let pods = loop {
            let partitioned = cfg.state.read().is_ok_and(|g| g.disrupted());
            match kube.pods(&cfg.selector).await {
                Ok(p) if !partitioned && all_ready(&p, cfg.expected_pods) => break p,
                Ok(_) => {}
                Err(e) => warn!(error = %e, "chaos: cannot list pods"),
            }
            if !sleep_until_deadline(POLL, deadline).await {
                return Ok(());
            }
        };
        let Some(victim) = pick_victim(&pods, previous.as_deref()) else {
            continue;
        };
        let (name, old_uid) = (victim.metadata.name.clone(), victim.metadata.uid.clone());

        seq += 1;
        let killed = Instant::now();
        if let Err(e) = kube.delete(&name).await {
            warn!(pod = %name, error = %e, "chaos: cannot delete pod");
            seq -= 1;
            continue;
        }
        info!(pod = %name, seq, "chaos: pod deleted");
        previous = Some(name.clone());
        if let Ok(mut g) = cfg.state.write() {
            g.chaos.totals.kills += 1;
            g.chaos.events.push(ChaosEvent {
                seq,
                pod: name.clone(),
                at_secs: cfg.start.elapsed().as_secs(),
                recovery_secs: None,
                timed_out: false,
            });
            let extra = g.chaos.events.len().saturating_sub(MAX_EVENTS);
            g.chaos.events.drain(..extra);
        }

        // Back = a new pod (different uid) of that name that is ready, and
        // the rest of the cluster ready as well.
        let back = loop {
            if killed.elapsed() >= cfg.recovery_timeout {
                break false;
            }
            if let Ok(p) = kube.pods(&cfg.selector).await
                && all_ready(&p, cfg.expected_pods)
                && p.iter()
                    .any(|x| x.metadata.name == name && x.metadata.uid != old_uid)
            {
                break true;
            }
            if !sleep_until_deadline(POLL, deadline).await {
                return Ok(());
            }
        };
        let took = killed.elapsed().as_secs();
        if back {
            info!(pod = %name, secs = took, "chaos: cluster recovered");
        } else {
            warn!(pod = %name, secs = took, "chaos: cluster did not recover in time");
        }
        update_event(&cfg, seq, |e| {
            e.recovery_secs = back.then_some(took);
            e.timed_out = !back;
        });
        if let Ok(mut g) = cfg.state.write() {
            let t = &mut g.chaos.totals;
            if back {
                t.recovered += 1;
                t.last_recovery_secs = took;
                t.max_recovery_secs = t.max_recovery_secs.max(took);
            } else {
                t.timed_out += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(name: &str, ready: bool) -> Pod {
        Pod {
            metadata: Meta {
                name: name.into(),
                uid: format!("uid-{name}"),
                deletion_timestamp: None,
            },
            status: Status {
                conditions: vec![Condition {
                    kind: "Ready".into(),
                    status: if ready { "True" } else { "False" }.into(),
                }],
                container_statuses: Vec::new(),
            },
        }
    }

    #[test]
    fn victims_rotate_in_name_order() {
        let pods = vec![pod("ks-0", true), pod("ks-1", true), pod("ks-2", true)];
        let name = |p: Option<&str>| pick_victim(&pods, p).map(|x| x.metadata.name.clone());
        assert_eq!(name(None).as_deref(), Some("ks-0"));
        assert_eq!(name(Some("ks-0")).as_deref(), Some("ks-1"));
        assert_eq!(name(Some("ks-2")).as_deref(), Some("ks-0"));
        assert_eq!(name(Some("gone")).as_deref(), Some("ks-0"));
        assert!(pick_victim(&[], None).is_none());
    }

    #[test]
    fn needs_all_pods_ready() {
        let ok = vec![pod("a", true), pod("b", true)];
        assert!(all_ready(&ok, 2));
        assert!(!all_ready(&ok, 3));
        assert!(!all_ready(&[pod("a", true), pod("b", false)], 2));
        let mut terminating = pod("a", true);
        terminating.metadata.deletion_timestamp = Some("now".into());
        assert!(!all_ready(&[terminating], 1));
    }

    #[test]
    fn knows_when_a_statefulset_is_rolled_out() {
        let json = |obs: i64, updated: i64, ready: i64, current: &str| {
            format!(
                r#"{{"metadata":{{"generation":3}},"spec":{{"replicas":3}},
                "status":{{"observedGeneration":{obs},"updatedReplicas":{updated},
                "readyReplicas":{ready},"currentRevision":"{current}","updateRevision":"r2"}}}}"#
            )
        };
        let parse = |j: String| serde_json::from_str::<StatefulSet>(&j).expect("valid json");
        assert!(parse(json(3, 3, 3, "r2")).rolled_out());
        assert!(!parse(json(2, 3, 3, "r2")).rolled_out());
        assert!(!parse(json(3, 1, 3, "r2")).rolled_out());
        assert!(!parse(json(3, 3, 2, "r2")).rolled_out());
        assert!(!parse(json(3, 3, 3, "r1")).rolled_out());
    }

    #[test]
    fn parses_pod_list() {
        let json = r#"{"items":[{"metadata":{"name":"ks-0","uid":"u"},
            "status":{"conditions":[{"type":"Ready","status":"True"}],
            "containerStatuses":[{"restartCount":2},{"restartCount":1}]}}]}"#;
        let list: PodList = serde_json::from_str(json).expect("valid json");
        assert!(list.items[0].ready());
        assert_eq!(list.items[0].restarts(), 3);
    }
}
