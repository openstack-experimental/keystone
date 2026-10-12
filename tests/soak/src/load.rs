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

//! Load generation in phases by driving the `load_test` (goose) binary.
//!
//! Phases cycle for the whole run so the profile includes bursts and idle
//! time, during which compaction and purging can run.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use tokio::time::Instant;
use tracing::{info, warn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Steady,
    Burst,
    Idle,
}

#[derive(Clone, Copy, Debug)]
pub struct Phase {
    pub kind: Kind,
    pub length: Duration,
}

/// Parse `steady:5m,burst:1m,idle:5m`.
pub fn parse_phases(spec: &str) -> Result<Vec<Phase>> {
    let mut phases = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (kind, len) = part
            .split_once(':')
            .with_context(|| format!("phase `{part}` must look like `kind:duration`"))?;
        let kind = match kind {
            "steady" => Kind::Steady,
            "burst" => Kind::Burst,
            "idle" => Kind::Idle,
            other => bail!("unknown phase kind `{other}` (steady|burst|idle)"),
        };
        let length = humantime::parse_duration(len)?;
        if length.is_zero() {
            bail!("phase `{part}` has zero length");
        }
        phases.push(Phase { kind, length });
    }
    if phases.is_empty() {
        bail!("no load phases configured");
    }
    Ok(phases)
}

pub struct LoadConfig {
    pub command: String,
    pub host: String,
    pub steady_users: usize,
    pub burst_users: usize,
    pub phases: Vec<Phase>,
}

/// Run phases in a loop until `deadline` (forever when `None`). Returns an
/// error as soon as the load generator fails to run, which the caller treats
/// as a violation.
pub async fn run(cfg: LoadConfig, deadline: Option<Instant>) -> Result<()> {
    for phase in cfg.phases.iter().cycle() {
        let mut length = phase.length;
        if let Some(d) = deadline {
            let left = d.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(());
            }
            length = length.min(left);
        }
        let users = match phase.kind {
            Kind::Steady => cfg.steady_users,
            Kind::Burst => cfg.burst_users,
            Kind::Idle => {
                info!(?length, "load phase: idle");
                tokio::time::sleep(length).await;
                continue;
            }
        };
        info!(kind = ?phase.kind, users, ?length, "load phase");
        let status = Command::new(&cfg.command)
            .arg("--host")
            .arg(&cfg.host)
            .arg("--users")
            .arg(users.to_string())
            .arg("--hatch-rate")
            .arg((users / 5).max(1).to_string())
            .arg("--run-time")
            .arg(format!("{}s", length.as_secs().max(1)))
            .arg("--no-reset-metrics")
            .arg("--quiet")
            .kill_on_drop(true)
            .status()
            .await
            .with_context(|| format!("cannot run `{}`", cfg.command))?;
        if !status.success() {
            warn!(%status, "load generator failed");
            bail!("load generator exited with {status}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_phase_spec() {
        let p = parse_phases("steady:5m, burst:30s,idle:1h").unwrap_or_default();
        assert_eq!(p.len(), 3);
        assert_eq!(p[1].kind, Kind::Burst);
        assert_eq!(p[1].length, Duration::from_secs(30));
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(parse_phases("").is_err());
        assert!(parse_phases("fast:1m").is_err());
        assert!(parse_phases("steady").is_err());
        assert!(parse_phases("steady:0s").is_err());
    }
}
