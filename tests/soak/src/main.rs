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

mod canary;
mod chaos;
mod invariants;
mod load;
mod partition;
mod prom;
mod report;
mod server;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{error, info, warn};

use crate::invariants::{Evaluator, NodeObservation, Thresholds, Violation};
use crate::report::Sample;
use crate::server::{Shared, Verdict};

/// Maximum number of violations kept in the verdict.
const MAX_VIOLATIONS: usize = 100;

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the report of a running controller and exit with 0 when it is
    /// healthy, 1 when unhealthy, 2 when it cannot be reached. Meant for
    /// `kubectl exec deploy/keystone-soak -- soak report`.
    Report {
        /// Controller address.
        #[arg(long, env = "SOAK_REPORT_URL", default_value = "http://127.0.0.1:9100")]
        url: String,
        /// Print the complete state as JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

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
    /// Delete one Raft pod this often while the load runs (`0` disables).
    /// Needs RBAC to delete pods, see `overlays/soak/soak.yaml`.
    #[arg(long, env = "SOAK_CHAOS_INTERVAL", default_value = "0s", value_parser = humantime::parse_duration)]
    chaos_interval: Duration,
    /// A deleted pod must be ready again within this time.
    #[arg(long, env = "SOAK_CHAOS_RECOVERY", default_value = "5m", value_parser = humantime::parse_duration)]
    chaos_recovery: Duration,
    /// Label selector of the Raft pods chaos may delete.
    #[arg(
        long,
        env = "SOAK_CHAOS_SELECTOR",
        default_value = "app.kubernetes.io/name=keystone-rs"
    )]
    chaos_selector: String,
    /// Cut one Raft node off from its peers this often (`0` disables).
    /// Needs RBAC for network policies, see `overlays/soak/soak.yaml`, and a
    /// CNI that enforces them (k3s does).
    #[arg(long, env = "SOAK_PARTITION_INTERVAL", default_value = "0s", value_parser = humantime::parse_duration)]
    partition_interval: Duration,
    /// How long the node stays cut off.
    #[arg(long, env = "SOAK_PARTITION_DURATION", default_value = "60s", value_parser = humantime::parse_duration)]
    partition_duration: Duration,
    /// The other nodes must lead and accept writes within this time.
    #[arg(long, env = "SOAK_PARTITION_ELECTION", default_value = "60s", value_parser = humantime::parse_duration)]
    partition_election: Duration,
    /// The cluster must converge within this time after the cut is lifted.
    #[arg(long, env = "SOAK_PARTITION_RECOVERY", default_value = "3m", value_parser = humantime::parse_duration)]
    partition_recovery: Duration,
    /// Write and verify a canary record this often (`0` disables). Each
    /// record is read back from every node (read-after-write) and the
    /// earlier ones are re-checked (integrity).
    #[arg(long, env = "SOAK_CANARY_INTERVAL", default_value = "0s", value_parser = humantime::parse_duration)]
    canary_interval: Duration,
    /// Port of the keystone API on every pod.
    #[arg(long, env = "SOAK_API_PORT", default_value_t = 8080)]
    api_port: u16,
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
    /// Disk spread is only judged when every node holds at least this many
    /// bytes (journal preallocation makes small stores differ a lot).
    #[arg(
        long,
        env = "SOAK_MIN_DISK_FOR_SPREAD",
        default_value_t = 1_073_741_824.0
    )]
    min_disk_for_spread: f64,
    /// Allowed share of failed requests per load phase (0.01 = 1 %). Expected
    /// negative responses and throttling (429) are not failures.
    #[arg(long, env = "SOAK_MAX_LOAD_ERROR_RATE", default_value_t = 0.01)]
    max_load_error_rate: f64,
    /// Load phases with fewer requests are too small to judge.
    #[arg(long, env = "SOAK_MIN_LOAD_REQUESTS", default_value_t = 100)]
    min_load_requests: u64,
}

/// Write to stdout without `println!` (denied by the lints).
fn out(text: &str) {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
}

/// `soak report`: fetch the report from the local controller.
async fn print_report(url: &str, json: bool) -> i32 {
    let format = if json { "json" } else { "md" };
    let resp = match reqwest::get(format!(
        "{}/report?format={format}",
        url.trim_end_matches('/')
    ))
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "cannot reach the soak controller");
            return 2;
        }
    };
    let status = resp.status();
    match resp.text().await {
        Ok(body) => out(&body),
        Err(e) => {
            error!(error = %e, "cannot read the report");
            return 2;
        }
    }
    match status.as_u16() {
        200 => 0,
        503 => 1,
        _ => 2,
    }
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

/// Judge the error rate of load phases that finished since the last call.
fn check_load(state: &Shared, checked: &mut u64, now: Duration, args: &Args) -> Vec<Violation> {
    let Ok(g) = state.read() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let already = *checked;
    for p in g.phases.iter().filter(|p| p.seq > already) {
        *checked = p.seq;
        let Some(s) = &p.summary else { continue };
        if s.requests < args.min_load_requests {
            continue;
        }
        let rate = s.failed as f64 / s.requests as f64;
        if rate > args.max_load_error_rate {
            let worst = s
                .failing_endpoints
                .first()
                .map(|e| format!("; worst: {} ({} failed)", e.name, e.failed))
                .unwrap_or_default();
            found.push(Violation {
                at_secs: now.as_secs(),
                check: "load_errors",
                detail: format!(
                    "{} phase {}: {} of {} requests failed ({:.2} %, limit {:.2} %), {} transport errors{worst}",
                    p.kind,
                    p.seq,
                    s.failed,
                    s.requests,
                    rate * 100.0,
                    args.max_load_error_rate * 100.0,
                    s.transport_errors,
                ),
            });
        }
    }
    found
}

/// Judge the recovery of chaos kills that were settled since the last call.
fn check_chaos(state: &Shared, checked: &mut u64, now: Duration, args: &Args) -> Vec<Violation> {
    let Ok(g) = state.read() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let already = *checked;
    for e in g.chaos.events.iter().filter(|e| e.seq > already) {
        // A kill that is still recovering is judged when it settles.
        if e.recovery_secs.is_none() && !e.timed_out {
            break;
        }
        *checked = e.seq;
        if e.timed_out {
            found.push(Violation {
                at_secs: now.as_secs(),
                check: "chaos_recovery",
                detail: format!(
                    "pod {} (kill {}) was not ready again within {}",
                    e.pod,
                    e.seq,
                    humantime::format_duration(args.chaos_recovery)
                ),
            });
        }
    }
    found
}

/// Report the failed checks of partitions that settled since the last call.
fn check_partition(state: &Shared, checked: &mut u64, now: Duration) -> Vec<Violation> {
    let Ok(g) = state.read() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let already = *checked;
    for e in g.partition.events.iter().filter(|e| e.seq > already) {
        // A partition that is still healing is judged when it settles.
        if !e.done {
            break;
        }
        *checked = e.seq;
        for f in &e.failures {
            found.push(Violation {
                at_secs: now.as_secs(),
                check: f.check,
                detail: format!("partition {} of {} {}: {}", e.seq, e.role, e.pod, f.detail),
            });
        }
    }
    found
}

/// Report canary failures recorded since the last call.
fn check_canary(state: &Shared, checked: &mut u64, now: Duration) -> Vec<Violation> {
    let Ok(g) = state.read() else {
        return Vec::new();
    };
    let already = *checked;
    let mut found = Vec::new();
    for f in g.canary.failures.iter().filter(|f| f.seq > already) {
        *checked = f.seq;
        found.push(Violation {
            at_secs: now.as_secs(),
            check: f.check,
            detail: f.detail.clone(),
        });
    }
    found
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
    if let Some(Command::Report { url, json }) = &args.command {
        std::process::exit(print_report(url, *json).await);
    }
    if args.interval.is_zero() {
        bail!("SOAK_INTERVAL must be > 0");
    }

    let start = Instant::now();
    let deadline = (!args.duration.is_zero()).then(|| start + args.duration);
    info!(duration = ?args.duration, interval = ?args.interval, "soak test starting");
    if args.expected_voters < 3 {
        warn!(
            voters = args.expected_voters,
            "fewer than 3 voters is not a production-like cluster, \
             deploy keystone with the `soak` skaffold profile"
        );
    }

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
            start,
            state: state.clone(),
        };
        Some(tokio::spawn(load::run(cfg, deadline)))
    };

    if !args.chaos_interval.is_zero() {
        let cfg = chaos::ChaosConfig {
            interval: args.chaos_interval,
            recovery_timeout: args.chaos_recovery,
            selector: args.chaos_selector.clone(),
            expected_pods: usize::try_from(args.expected_voters).unwrap_or(usize::MAX),
            start,
            state: state.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = chaos::run(cfg, deadline).await {
                error!(error = %format!("{e:#}"), "chaos task stopped");
            }
        });
    }

    if !args.partition_interval.is_zero() {
        let cfg = partition::PartitionConfig {
            interval: args.partition_interval,
            duration: args.partition_duration,
            election_timeout: args.partition_election,
            recovery_timeout: args.partition_recovery,
            selector: args.chaos_selector.clone(),
            expected_pods: usize::try_from(args.expected_voters).unwrap_or(usize::MAX),
            service: args.metrics_service.clone(),
            metrics_port: args.metrics_port,
            api_port: args.api_port,
            host: args.host.clone(),
            start,
            state: state.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = partition::run(cfg, deadline).await {
                error!(error = %format!("{e:#}"), "partition task stopped");
            }
        });
    }

    if !args.canary_interval.is_zero() {
        let cfg = canary::CanaryConfig {
            interval: args.canary_interval,
            host: args.host.clone(),
            api_port: args.api_port,
            start,
            state: state.clone(),
            service: args.metrics_service.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = canary::run(cfg, deadline).await {
                error!(error = %format!("{e:#}"), "canary task stopped");
            }
        });
    }

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
        min_disk_for_spread: args.min_disk_for_spread,
    });

    let mut ticker = tokio::time::interval(args.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut stop = Box::pin(terminate());
    let mut failed = false;
    // Highest load phase number already judged for its error rate.
    let mut checked_phase = 0u64;
    let mut checked_chaos = 0u64;
    let mut checked_partition = 0u64;
    let mut checked_canary = 0u64;

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
        found.extend(check_load(&state, &mut checked_phase, now, &args));
        found.extend(check_canary(&state, &mut checked_canary, now));
        found.extend(check_chaos(&state, &mut checked_chaos, now, &args));
        found.extend(check_partition(&state, &mut checked_partition, now));
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
            g.growth.record(Sample {
                at_secs: now.as_secs(),
                disk_bytes: summary.disk_bytes_total,
                log_bytes: summary.log_disk_bytes_total,
                snapshot_bytes: summary.snapshot_bytes_total,
            });
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

    // Leave the final report in the pod log, it survives a restart.
    if let Ok(g) = state.read() {
        out(&format!("\n{}\n", report::render_markdown(&g)));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{LoadSummary, PhaseRecord};

    fn state_with(requests: u64, failed: u64) -> Shared {
        let mut v = Verdict::default();
        v.phases.push(PhaseRecord {
            seq: 1,
            kind: "steady".into(),
            users: 20,
            start_secs: 0,
            length_secs: 300,
            summary: Some(LoadSummary {
                requests,
                failed,
                ..LoadSummary::default()
            }),
        });
        Arc::new(RwLock::new(v))
    }

    fn args() -> Args {
        Args::parse_from(["soak"])
    }

    #[test]
    fn flags_phase_over_error_rate_once() {
        let st = state_with(1000, 50);
        let mut checked = 0;
        let found = check_load(&st, &mut checked, Duration::from_secs(1), &args());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].check, "load_errors");
        assert!(check_load(&st, &mut checked, Duration::from_secs(2), &args()).is_empty());
    }

    #[test]
    fn flags_unrecovered_kill_once() {
        let st: Shared = Arc::new(RwLock::new(Verdict::default()));
        let event = |seq, recovery_secs, timed_out| chaos::ChaosEvent {
            seq,
            pod: format!("ks-{seq}"),
            at_secs: 0,
            recovery_secs,
            timed_out,
        };
        if let Ok(mut g) = st.write() {
            g.chaos.events = vec![
                event(1, Some(30), false),
                event(2, None, true),
                event(3, None, false),
            ];
        }
        let mut checked = 0;
        let found = check_chaos(&st, &mut checked, Duration::ZERO, &args());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].check, "chaos_recovery");
        // Kill 3 is still recovering and judged later.
        assert_eq!(checked, 2);
        assert!(check_chaos(&st, &mut checked, Duration::ZERO, &args()).is_empty());
    }

    #[test]
    fn reports_partition_failures_once_settled() {
        let st: Shared = Arc::new(RwLock::new(Verdict::default()));
        let event = |seq, done, failed: bool| partition::PartitionEvent {
            seq,
            pod: format!("ks-{seq}"),
            role: "leader",
            at_secs: 0,
            effective: true,
            heal_secs: Some(10),
            failures: if failed {
                vec![partition::PartitionFailure {
                    check: "partition_split_brain",
                    detail: "acknowledged a write".into(),
                }]
            } else {
                Vec::new()
            },
            done,
        };
        if let Ok(mut g) = st.write() {
            g.partition.events = vec![
                event(1, true, false),
                event(2, true, true),
                event(3, false, true),
            ];
        }
        let mut checked = 0;
        let found = check_partition(&st, &mut checked, Duration::ZERO);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].check, "partition_split_brain");
        assert_eq!(checked, 2);
        assert!(check_partition(&st, &mut checked, Duration::ZERO).is_empty());
    }

    #[test]
    fn reports_canary_failures_once() {
        let st: Shared = Arc::new(RwLock::new(Verdict::default()));
        if let Ok(mut g) = st.write() {
            g.canary.failures.push(canary::CanaryFailure {
                seq: 1,
                at_secs: 0,
                check: "read_after_write",
                detail: "x".into(),
            });
        }
        let mut checked = 0;
        assert_eq!(check_canary(&st, &mut checked, Duration::ZERO).len(), 1);
        assert!(check_canary(&st, &mut checked, Duration::ZERO).is_empty());
    }

    #[test]
    fn tolerates_low_rate_and_tiny_phases() {
        let mut checked = 0;
        let ok = state_with(1000, 5);
        assert!(check_load(&ok, &mut checked, Duration::ZERO, &args()).is_empty());
        let tiny = state_with(10, 10);
        let mut checked = 0;
        assert!(check_load(&tiny, &mut checked, Duration::ZERO, &args()).is_empty());
    }
}
