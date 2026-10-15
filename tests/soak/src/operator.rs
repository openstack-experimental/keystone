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

//! Run `keystone-manage storage ...` as the storage operator.
//!
//! Promoting, demoting and removing Raft members needs the `storage-operator`
//! identity, which the keystone pods and the soak controller deliberately do
//! not hold (see `tools/k8s/tests/keystone-raft-spiffe-id.yaml`). The test
//! cluster runs an operator Deployment for that. This module runs one command
//! at a time in a Job built from that Deployment's pod template, so the pod
//! carries the same labels, and therefore the same SPIFFE identity, and the
//! same image and configuration.
//!
//! Handing the soak controller the power to create such Jobs is the power of
//! the operator role: use it in test clusters only.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::Method;
use serde_json::{Value, json};
use tokio::time::Instant;

use crate::chaos::Kube;

const POLL: Duration = Duration::from_secs(2);

/// One row of `keystone-manage storage list-peers`.
#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub node_id: u64,
    pub leader: bool,
    pub voter: bool,
}

/// Parse the table printed by `list-peers`; rows are
/// `│ address ┆ node id ┆ leader ┆ voter │`.
pub fn parse_peers(output: &str) -> Vec<Peer> {
    output
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line
                .trim()
                .trim_matches('│')
                .split('┆')
                .map(str::trim)
                .collect();
            if cells.len() != 4 {
                return None;
            }
            Some(Peer {
                node_id: cells[1].parse().ok()?,
                leader: cells[2] == "yes",
                voter: cells[3] == "yes",
            })
        })
        .collect()
}

/// The Job that runs `keystone-manage storage <args>` from the operator
/// Deployment's pod `template`.
pub fn build_job(template: &Value, name: &str, args: &[&str]) -> Result<Value> {
    let mut template = template.clone();
    let spec = template
        .get_mut("spec")
        .context("the operator Deployment has no pod spec")?;
    spec["restartPolicy"] = json!("Never");
    let container = spec
        .get_mut("containers")
        .and_then(|c| c.get_mut(0))
        .context("the operator Deployment has no container")?;
    let mut command = vec!["keystone-manage", "storage"];
    command.extend_from_slice(args);
    container["command"] = json!(command);
    if let Some(c) = container.as_object_mut() {
        // The Deployment keeps `sleep infinity` alive with its own probes.
        c.remove("readinessProbe");
        c.remove("livenessProbe");
        c.remove("args");
    }
    Ok(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "labels": {"app.kubernetes.io/managed-by": "keystone-soak"},
        },
        "spec": {
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 600,
            "template": template,
        },
    }))
}

/// What a command printed and whether it succeeded.
pub struct Output {
    pub success: bool,
    pub log: String,
}

pub struct Operator<'a> {
    pub kube: &'a Kube,
    /// Name of the operator Deployment.
    pub deployment: &'a str,
}

impl Operator<'_> {
    /// Run `keystone-manage storage <args>` and wait for it to finish.
    pub async fn run(&self, args: &[&str], timeout: Duration) -> Result<Output> {
        let ns = self.kube.namespace().to_string();
        let deployment = self
            .kube
            .json(
                Method::GET,
                &format!(
                    "/apis/apps/v1/namespaces/{ns}/deployments/{}",
                    self.deployment
                ),
                None,
            )
            .await
            .context("cannot read the operator Deployment")?;
        let name = format!(
            "soak-op-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis())
        );
        let job = build_job(&deployment["spec"]["template"], &name, args)?;
        let jobs = format!("/apis/batch/v1/namespaces/{ns}/jobs");
        self.kube.json(Method::POST, &jobs, Some(&job)).await?;

        let began = Instant::now();
        let outcome = loop {
            let status = self
                .kube
                .json(Method::GET, &format!("{jobs}/{name}"), None)
                .await?;
            let count = |k: &str| status["status"][k].as_u64().unwrap_or(0);
            if count("succeeded") > 0 {
                break Some(true);
            }
            if count("failed") > 0 {
                break Some(false);
            }
            if began.elapsed() >= timeout {
                break None;
            }
            tokio::time::sleep(POLL).await;
        };

        let log = self.log(&ns, &name).await.unwrap_or_default();
        let _ = self
            .kube
            .json(
                Method::DELETE,
                &format!("{jobs}/{name}?propagationPolicy=Background"),
                None,
            )
            .await;
        match outcome {
            Some(success) => Ok(Output { success, log }),
            None => bail!("`storage {}` did not finish in time", args.join(" ")),
        }
    }

    async fn log(&self, ns: &str, job: &str) -> Result<String> {
        let pods = self
            .kube
            .json(
                Method::GET,
                &format!("/api/v1/namespaces/{ns}/pods?labelSelector=job-name%3D{job}"),
                None,
            )
            .await?;
        let pod = pods["items"][0]["metadata"]["name"]
            .as_str()
            .context("the job has no pod")?;
        self.kube
            .text(&format!("/api/v1/namespaces/{ns}/pods/{pod}/log"))
            .await
    }

    /// The members of the cluster.
    pub async fn peers(&self, timeout: Duration) -> Result<Vec<Peer>> {
        let out = self.run(&["list-peers"], timeout).await?;
        if !out.success {
            bail!("`storage list-peers` failed: {}", out.log.trim());
        }
        Ok(parse_peers(&out.log))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "╭──┬──╮\n│ Address ┆ Node ID ┆ Leader ┆ Voter │\n╞══╪══╡\n\
        │ keystone-rs-0.svc:8300 ┆ 0       ┆ no     ┆ yes   │\n├╌╌┼╌╌┤\n\
        │ keystone-rs-3.svc:8300 ┆ 3       ┆ no     ┆ no    │\n\
        │ keystone-rs-2.svc:8300 ┆ 2       ┆ yes    ┆ yes   │\n╰──┴──╯\nMetrics \"x\"\n";

    #[test]
    fn parses_the_peer_table() {
        assert_eq!(
            parse_peers(TABLE),
            vec![
                Peer {
                    node_id: 0,
                    leader: false,
                    voter: true
                },
                Peer {
                    node_id: 3,
                    leader: false,
                    voter: false
                },
                Peer {
                    node_id: 2,
                    leader: true,
                    voter: true
                },
            ]
        );
        assert!(parse_peers("nothing here").is_empty());
    }

    #[test]
    fn builds_a_job_from_the_operator_template() {
        let template = json!({
            "metadata": {"labels": {"app.kubernetes.io/name": "keystone-storage-operator"}},
            "spec": {"containers": [{
                "name": "operator",
                "image": "keystone-rs",
                "command": ["sleep", "infinity"],
                "readinessProbe": {"exec": {"command": ["true"]}},
            }]},
        });
        let job = build_job(&template, "soak-op-1", &["promote", "1"]).expect("job");
        let pod = &job["spec"]["template"];
        assert_eq!(pod["spec"]["restartPolicy"], "Never");
        assert_eq!(
            pod["spec"]["containers"][0]["command"],
            json!(["keystone-manage", "storage", "promote", "1"])
        );
        assert!(pod["spec"]["containers"][0].get("readinessProbe").is_none());
        // The label that grants the operator identity is kept.
        assert_eq!(
            pod["metadata"]["labels"]["app.kubernetes.io/name"],
            "keystone-storage-operator"
        );
        assert!(build_job(&json!({}), "x", &[]).is_err());
    }
}
