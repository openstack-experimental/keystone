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

//! Shutdown signal handling and the listener-task join loop.

use std::time::Instant;

use tokio::signal;
use tokio::task::JoinSet;
use tracing::{error, info};

use super::Startup;
use openstack_keystone_core::keystone::ServiceState;

/// Spawn the task that watches for `SIGINT`/`SIGTERM` and, on receipt,
/// terminates the service and cancels the process-wide shutdown token.
pub fn spawn_watcher(startup: &Startup) {
    let shutdown_token = startup.token.clone();
    let state = startup.state.clone();
    tokio::spawn(async move {
        shutdown_signal(state).await;
        shutdown_token.cancel();
    });
}

/// Block until the first listener task in `handles` exits (normally or with
/// a panic/abort), log the outcome, then drain the rest.
///
/// The caller cancels the shutdown token afterwards so any tasks not tracked
/// by this `JoinSet` also stop.
pub async fn await_listeners(mut handles: JoinSet<()>) {
    info!("Waiting on {} listener tasks in JoinSet", handles.len());
    let join_start = Instant::now();
    let result = handles.join_next().await;
    let elapsed = join_start.elapsed().as_secs_f32();
    match result {
        Some(Ok(())) => info!(
            "One listener task exited normally after {:.3}s, remaining tasks: {}. Cancelling all.",
            elapsed,
            handles.len()
        ),
        Some(Err(e)) => error!(
            "One listener task failed after {:.3}s with: {}. Remaining tasks: {}. Cancelling all.",
            elapsed,
            if e.is_panic() {
                format!("Panic: {:?}", e.into_panic())
            } else {
                "JoinError (task aborted)".to_string()
            },
            handles.len()
        ),
        None => error!(
            "JoinSet is empty after {:.3}s — no tasks to wait on.",
            elapsed
        ),
    }
    handles.join_all().await;
}

/// Resolve once `SIGINT` (Ctrl+C) or `SIGTERM` is received, terminating the
/// service state in the process.
async fn shutdown_signal(state: ServiceState) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .inspect_err(|e| error!("failed to install Ctrl+C handler: {e}"))
            .ok();
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::terminate())
            .inspect_err(|e| error!("failed to install signal handler: {e}"))
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => { state.terminate().await.ok(); },
        () = terminate => { state.terminate().await.ok(); },
    }
}
