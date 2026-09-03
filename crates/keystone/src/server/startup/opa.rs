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

//! Embedded OPA subprocess supervision: spawn `opa run -s`, forward its
//! stdout/stderr to `tracing`, block until `/health` is green, and stop it
//! on shutdown.

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use color_eyre::eyre::{Report, Result, WrapErr};
use tokio::io::{AsyncBufReadExt as _, AsyncRead, BufReader};
use tokio::task::JoinSet;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};
use url::Url;

use super::Startup;

/// OPA readiness poll budget.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Launch the local OPA subprocess when `api_policy.opa_policies_path` is
/// configured, capture its log output, and wait for it to become ready
/// before returning.
///
/// This prevents a race where Keystone listeners accept requests (and run
/// policy checks) before the embedded OPA is actually serving.
pub async fn spawn(startup: &Startup, handles: &mut JoinSet<()>) -> Result<(), Report> {
    let cfg = &startup.cfg;
    let Some(policies_path) = &cfg.api_policy.opa_policies_path else {
        return Ok(());
    };
    let opa_url = cfg.api_policy.opa_base_url.clone();
    let (addr, socket_path) = resolve_listen_addr(&opa_url);
    let health_url = resolve_health_url(&opa_url, socket_path.as_deref());
    let health_client = build_health_client(socket_path.as_deref())?;

    info!(
        "Starting OPA subprocess with policies from {:?} listening on {}",
        policies_path, addr
    );
    let mut opa_cmd = tokio::process::Command::new("opa");
    opa_cmd
        .arg("run")
        .arg("-s")
        .arg(policies_path)
        .arg("--addr")
        .arg(&addr)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = opa_cmd.spawn().wrap_err_with(|| {
        "failed to start OPA subprocess: is `opa` installed and on PATH?".to_string()
    })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre::eyre!("OPA stdout pipe unexpectedly missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| eyre::eyre!("OPA stderr pipe unexpectedly missing"))?;

    // Poll `/health` before spawning the log pumps: the pumps must keep
    // draining the pipes even after we return so the child can't block on a
    // full pipe and deadlock.
    let ready = time::timeout(
        READY_TIMEOUT,
        wait_until_ready(health_client, health_url.clone()),
    )
    .await;

    handles.spawn(forward_opa_output(stdout, OutputStream::Stdout));
    handles.spawn(forward_opa_output(stderr, OutputStream::Stderr));

    if ready.is_err() {
        error!(
            error_msg = "OPA subprocess failed to become healthy within timeout",
            timeout_secs = READY_TIMEOUT.as_secs(),
            addr = %addr,
            "OPA did not become healthy"
        );
        info!("the health url used was: {}", health_url);
        return Err(eyre::eyre!(
            "OPA did not become healthy within {} seconds",
            READY_TIMEOUT.as_secs()
        ));
    }

    info!(
        "OPA subprocess is ready on {}, health: {}",
        addr, health_url
    );
    spawn_supervisor(child, startup.token.clone(), handles);
    Ok(())
}

/// Resolve the `--addr` argument OPA is started with, plus the Unix socket
/// path when the configured URL uses a socket scheme.
fn resolve_listen_addr(opa_url: &Url) -> (String, Option<PathBuf>) {
    let tcp_addr = || {
        format!(
            "{}:{}",
            opa_url.host_str().unwrap_or("0.0.0.0"),
            opa_url.port().unwrap_or(8181)
        )
    };
    match opa_url.scheme() {
        "unix" | "http+unix" => (
            format!("unix://{}", opa_url.path()),
            Some(PathBuf::from(opa_url.path())),
        ),
        _ => (tcp_addr(), None),
    }
}

/// The URL the readiness poll hits. Over a Unix socket the host is
/// irrelevant (the client is bound to the socket), so a fixed
/// `http://localhost/health` is used.
fn resolve_health_url(opa_url: &Url, socket_path: Option<&Path>) -> Url {
    match socket_path {
        Some(_) =>
        {
            #[allow(clippy::unwrap_used)]
            "http://localhost/health".parse().unwrap()
        }
        None => opa_url.join("/health").unwrap_or_else(|_| opa_url.clone()),
    }
}

/// Build the `reqwest` client for the health poll. When OPA listens on a
/// Unix socket the client must be bound to it with `.unix_socket()` so
/// requests are routed over the socket rather than TCP to localhost.
fn build_health_client(socket_path: Option<&Path>) -> Result<reqwest::Client, Report> {
    match socket_path {
        Some(socket_path) => reqwest::Client::builder()
            .unix_socket(socket_path.to_path_buf())
            .build()
            .wrap_err("failed to build reqwest client for OPA health check"),
        None => Ok(reqwest::Client::new()),
    }
}

/// Poll `health_url` with exponential back-off (capped at 1s) until it
/// answers with a success status. Runs under an external timeout.
async fn wait_until_ready(client: reqwest::Client, health_url: Url) {
    let mut backoff = Duration::from_millis(50);
    loop {
        tokio::time::sleep(backoff).await;
        match client.get(health_url.as_str()).send().await {
            Ok(resp) if resp.status().is_success() => return,
            Ok(resp) => {
                warn!(status = %resp.status(), "OPA health check returned non-success, retrying");
            }
            Err(e) => trace!(error = %e, "OPA not yet ready, retrying"),
        }
        backoff = backoff.saturating_mul(2).min(Duration::from_secs(1));
    }
}

#[derive(Clone, Copy)]
enum OutputStream {
    Stdout,
    Stderr,
}

impl OutputStream {
    fn name(self) -> &'static str {
        match self {
            OutputStream::Stdout => "stdout",
            OutputStream::Stderr => "stderr",
        }
    }
}

/// Forward every line the child writes on one pipe to `tracing` under the
/// `opa` target — `INFO` for stdout, `WARN` for stderr.
async fn forward_opa_output<R: AsyncRead + Unpin>(pipe: R, stream: OutputStream) {
    let mut reader = BufReader::new(pipe);
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(_) => match stream {
                OutputStream::Stdout => info!(target: "opa", "{}", buf.trim_end()),
                OutputStream::Stderr => warn!(target: "opa", "{}", buf.trim_end()),
            },
            Err(e) => {
                warn!(error = %e, "failed to read OPA {} line", stream.name());
                break;
            }
        }
    }
}

/// Spawn the task that owns the running `opa` child: it reaps a
/// self-initiated exit, and on shutdown signals and reaps the child so OPA
/// never outlives `main`'s `handles.join_all()` as an orphan.
fn spawn_supervisor(
    mut child: tokio::process::Child,
    cancel: CancellationToken,
    handles: &mut JoinSet<()>,
) {
    handles.spawn(async move {
        tokio::select! {
            result = child.wait() => match result {
                Ok(code) => {
                    if code.success() {
                        info!("OPA subprocess exited cleanly with status {}", code);
                    } else if let Some(exit_code) = code.code() {
                        error!(exit_code, "OPA subprocess exited with error code");
                    } else if let Some(signal) = code.signal() {
                        error!(signal, "OPA subprocess was killed by signal");
                    } else {
                        error!("OPA subprocess exited abnormally (status unknown)");
                    }
                }
                Err(e) => error!(error = %e, "failed to wait on OPA subprocess"),
            },
            () = cancel.cancelled() => {
                info!("Shutdown requested, stopping OPA subprocess");
                if let Err(e) = child.start_kill() {
                    error!(error = %e, "failed to signal OPA subprocess to stop");
                }
                if let Err(e) = child.wait().await {
                    error!(error = %e, "failed to reap OPA subprocess after shutdown");
                }
            }
        }
    });
}
