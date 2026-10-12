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

//! Raft soak test controller.
//!
//! Drives the goose `load_test` in phases against a keystone cluster and, in
//! parallel, scrapes every Raft node's `/metrics` and `/ready`, judges cluster
//! health and storage growth, and publishes the result as Prometheus metrics
//! and a JSON verdict. See `tests/soak/README.md`.

mod invariants;
mod load;
mod prom;
mod server;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{error, info, warn};

use crate::invariants::{Evaluator, NodeObservation, Thresholds, Violation};
use crate::server::{Shared, Verdict};

/// Maximum number of violations kept in the verdict.
const MAX_VIOLATIONS: usize = 100;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Total run length, e.g. `30m`, `24h`, `7d`. `0` runs until stopped.
    #[arg(long, env = "SOAK_DURATION", default_value = "1h", value_parser = humantime::parse_duration)]
    duration: Duration,
    /// Time between evaluation cycles.
    #[arg(long, env = "SOAK_INTERVAL", default_value = "30s", value_parser = humantime::parse_duration)]
    interval: Duration,
    /// Stop at the first violation (exit code 1) instead of recording it.
    #[arg(long, env = "SOAK_FAIL_FAST", default_value_t = true, action = clap::ArgAction::Set)]
    fail_fast: bool,
    /// Keep serving metrics for this long after the run finished.
    #[arg(long, env = "SOAK_LINGER", default_value = "0s", value_parser = humantime::parse_duration)]
    linger: Duration,
    /// Address for the controller's `/metrics` and `/verdict`.
    #[arg(long, env = "SOAK_LISTEN", default_value = "0.0.0.0:9100")]
    listen: String,

    /// Headless service resolving to all keystone pods.
    #[arg(
        long,
        env = "SOAK_METRICS_SERVICE",
        default_value = "keystone-rs-internal"
    )]
    metrics_service: String,
    /// Port of the keystone metrics/health listener.
    #[arg(long, env = "SOAK_METRICS_PORT", default_value_t = 8099)]
    metrics_port: u16,
    /// Explicit `host:port` metrics targets, overriding DNS discovery.
    #[arg(long, env = "SOAK_TARGETS", value_delimiter = ',')]
    targets: Vec<String>,

    /// Keystone API URL the load generator talks to.
    #[arg(long, env = "SOAK_HOST", default_value = "http://keystone-rs:8080")]
    host: String,
    /// Load generator binary. Reads the `OS_*` auth variables.
    #[arg(long, env = "SOAK_LOAD_COMMAND", default_value = "load_test")]
    load_command: String,
    /// Load profile, repeated for the whole run.
    #[arg(
        long,
        env = "SOAK_PHASES",
        default_value = "steady:5m,burst:1m,idle:5m"
    )]
    phases: String,
    #[arg(long, env = "SOAK_STEADY_USERS", default_value_t = 20)]
    steady_users: usize,
    #[arg(long, env = "SOAK_BURST_USERS", default_value_t = 100)]
    burst_users: usize,
    /// Do not generate load, only watch the cluster.
    #[arg(long, env = "SOAK_NO_LOAD", default_value_t = false, action = clap::ArgAction::Set)]
    no_load: bool,

    /// Expected number of Raft voters.
    #[arg(long, env = "SOAK_EXPECTED_VOTERS", default_value_t = 3)]
    expected_voters: u64,
    /// A failing condition must persist this long to count (elections etc.).
    #[arg(long, env = "SOAK_GRACE", default_value = "2m", value_parser = humantime::parse_duration)]
    grace: Duration,
    #[arg(long, env = "SOAK_LEARNER_GRACE", default_value = "10m", value_parser = humantime::parse_duration)]
    learner_grace: Duration,
    #[arg(long, env = "SOAK_MAX_APPLIED_SPREAD", default_value_t = 1000)]
    max_applied_spread: u64,
    #[arg(long, env = "SOAK_MAX_APPLY_LAG", default_value_t = 1000)]
    max_apply_lag: u64,
    #[arg(long, env = "SOAK_MAX_REPLICATION_LAG", default_value_t = 1000)]
    max_replication_lag: u64,
    /// Growth trends are ignored for this long after start.
    #[arg(long, env = "SOAK_WARMUP", default_value = "30m", value_parser = humantime::parse_duration)]
    warmup: Duration,
    /// Window over which log growth is judged.
    #[arg(long, env = "SOAK_GROWTH_WINDOW", default_value = "1h", value_parser = humantime::parse_duration)]
    growth_window: Duration,
    /// Allowed relative log growth within the window (0.5 = +50 %).
    #[arg(long, env = "SOAK_MAX_LOG_GROWTH", default_value_t = 0.5)]
    max_log_growth: f64,
    /// Allowed max/min disk usage ratio between nodes.
    #[arg(long, env = "SOAK_MAX_DISK_SPREAD", default_value_t = 2.0)]
    max_disk_spread: f64,
}

async fn discover(args: &Args) -> Vec<String> {
    if !args.targets.is_empty() {
        return args.targets.clone();
    }
    match tokio::net::lookup_host((args.metrics_service.as_str(), args.metrics_port)).await {
        Ok(addrs) => {
            let mut v: Vec<String> = addrs.map(|a| a.to_string()).collect();
            v.sort();
            v.dedup();
            v
        }
        Err(e) => {
            warn!(service = %args.metrics_service, error = %e, "cannot resolve metrics service");
            Vec::new()
        }
    }
}

async fn observe(client: &reqwest::Client, addr: String) -> NodeObservation {
    let scrape = async {
        let text = client
            .get(format!("http://{addr}/metrics"))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .text()
            .await
            .ok()?;
        Some(prom::parse(&text))
    }
    .await;
    let ready = client
        .get(format!("http://{addr}/ready"))
        .send()
        .await
        .ok()
        .map(|r| r.status().is_success());
    NodeObservation {
        addr,
        scrape,
        ready,
    }
}

async fn observe_all(client: &reqwest::Client, addrs: Vec<String>) -> Vec<NodeObservation> {
    let mut set = JoinSet::new();
    for a in addrs {
        let c = client.clone();
        set.spawn(async move { observe(&c, a).await });
    }
    let mut out = Vec::new();
    while let Some(Ok(o)) = set.join_next().await {
        out.push(o);
    }
    out.sort_by(|a, b| a.addr.cmp(&b.addr));
    out
}

async fn terminate() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            tokio::select! { _ = s.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    if args.interval.is_zero() {
        bail!("SOAK_INTERVAL must be > 0");
    }

    let start = Instant::now();
    let deadline = (!args.duration.is_zero()).then(|| start + args.duration);
    info!(duration = ?args.duration, interval = ?args.interval, "soak test starting");

    let state: Shared = Arc::new(RwLock::new(Verdict {
        healthy: true,
        ..Verdict::default()
    }));
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("cannot listen on {}", args.listen))?;
    let app = server::router(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!(error = %e, "http server stopped");
        }
    });

    let mut load_task = if args.no_load {
        None
    } else {
        let cfg = load::LoadConfig {
            command: args.load_command.clone(),
            host: args.host.clone(),
            steady_users: args.steady_users,
            burst_users: args.burst_users,
            phases: load::parse_phases(&args.phases)?,
        };
        Some(tokio::spawn(load::run(cfg, deadline)))
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut evaluator = Evaluator::new(Thresholds {
        expected_voters: args.expected_voters,
        grace: args.grace,
        learner_grace: args.learner_grace,
        max_applied_spread: args.max_applied_spread,
        max_apply_lag: args.max_apply_lag,
        max_replication_lag: args.max_replication_lag,
        warmup: args.warmup,
        growth_window: args.growth_window,
        max_log_growth_ratio: args.max_log_growth,
        max_disk_spread_ratio: args.max_disk_spread,
    });

    let mut ticker = tokio::time::interval(args.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut stop = Box::pin(terminate());
    let mut failed = false;

    loop {
        let mut load_failure: Option<String> = None;
        let load_result = {
            let load_wait = async {
                match load_task.as_mut() {
                    Some(t) => t.await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = ticker.tick() => None,
                _ = &mut stop => {
                    warn!("terminated before the deadline");
                    std::process::exit(2);
                }
                res = load_wait => Some(res),
            }
        };
        if let Some(res) = load_result {
            load_task = None;
            match res {
                Ok(Ok(())) => info!("load generator finished"),
                Ok(Err(e)) => load_failure = Some(format!("{e:#}")),
                Err(e) => load_failure = Some(format!("load task panicked: {e}")),
            }
        }

        let now = start.elapsed();
        let addrs = discover(&args).await;
        let nodes = observe_all(&client, addrs).await;
        let (summary, mut found) = evaluator.evaluate(now, &nodes);
        if let Some(detail) = load_failure {
            found.push(Violation {
                at_secs: now.as_secs(),
                check: "load",
                detail,
            });
        }
        for v in &found {
            error!(check = v.check, detail = %v.detail, "invariant violated");
        }
        failed |= !found.is_empty();
        let finished = deadline.is_some_and(|d| Instant::now() >= d);
        if let Ok(mut g) = state.write() {
            g.healthy = !failed;
            g.finished = finished || (failed && args.fail_fast);
            g.elapsed_secs = now.as_secs();
            g.cycles += 1;
            g.violations_total += found.len() as u64;
            g.summary = summary;
            let room = MAX_VIOLATIONS.saturating_sub(g.violations.len());
            g.violations.extend(found.into_iter().take(room));
        }
        info!(
            elapsed = ?now,
            nodes = nodes.len(),
            healthy = !failed,
            "cycle complete"
        );
        if finished || (failed && args.fail_fast) {
            break;
        }
    }

    if !args.linger.is_zero() {
        info!(linger = ?args.linger, "serving final verdict");
        tokio::time::sleep(args.linger).await;
    }
    if failed {
        bail!("soak test failed, see /verdict");
    }
    info!("soak test passed");
    Ok(())
}
