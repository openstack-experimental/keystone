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
//! Observable, bounded wait for the SPIFFE Workload API.
//!
//! `spiffe::X509Source` retries the initial sync with backoff and neither
//! logs nor gives up when the Workload API is unreachable or serves no
//! matching SVID, which makes startup look hung. [`wait_for_spiffe_source`]
//! wraps such a future with progress logging and a deadline.

use std::fmt::Display;
use std::future::Future;
use std::time::Duration;

use eyre::{Result, eyre};
use tokio::time::{Instant, interval_at, sleep};
use tracing::{info, warn};

/// Upper bound for the initial SVID sync before startup fails.
pub const SPIFFE_INITIAL_SYNC_TIMEOUT: Duration = Duration::from_secs(120);

/// Interval between "still waiting" warnings.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

/// Await `source_init` (an `X509Source` construction) while logging progress.
///
/// `purpose` names the consumer (e.g. "Raft client mTLS") for the log lines.
/// Fails with a descriptive error after [`SPIFFE_INITIAL_SYNC_TIMEOUT`].
pub async fn wait_for_spiffe_source<T, E, F>(purpose: &str, source_init: F) -> Result<T>
where
    E: Display,
    F: Future<Output = Result<T, E>>,
{
    wait_with_timeout(purpose, SPIFFE_INITIAL_SYNC_TIMEOUT, source_init).await
}

async fn wait_with_timeout<T, E, F>(purpose: &str, timeout: Duration, source_init: F) -> Result<T>
where
    E: Display,
    F: Future<Output = Result<T, E>>,
{
    let socket = std::env::var("SPIFFE_ENDPOINT_SOCKET").unwrap_or_else(|_| "<unset>".into());
    info!(
        purpose,
        socket,
        timeout_secs = timeout.as_secs(),
        "Waiting for SPIFFE X509 SVID from the Workload API..."
    );
    let started = Instant::now();
    let mut progress = interval_at(started + PROGRESS_INTERVAL, PROGRESS_INTERVAL);
    let deadline = sleep(timeout);
    tokio::pin!(source_init, deadline);

    loop {
        tokio::select! {
            res = &mut source_init => {
                return match res {
                    Ok(source) => {
                        info!(
                            purpose,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "SPIFFE X509 source ready"
                        );
                        Ok(source)
                    }
                    Err(e) => Err(eyre!("SPIFFE X509Source init for {purpose} failed: {e}")),
                };
            }
            _ = &mut deadline => {
                return Err(eyre!(
                    "timed out after {}s waiting for a SPIFFE SVID for {purpose}; check that \
                     SPIFFE_ENDPOINT_SOCKET ({socket}) is reachable and that this workload \
                     has a registration entry (and matching SVID path) in SPIRE",
                    timeout.as_secs()
                ));
            }
            _ = progress.tick() => {
                warn!(
                    purpose,
                    socket,
                    elapsed_secs = started.elapsed().as_secs(),
                    "Still waiting for SPIFFE X509 SVID; Workload API unreachable or no \
                     matching SVID issued"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn times_out_when_source_never_ready() {
        let err = wait_with_timeout(
            "test",
            Duration::from_millis(50),
            std::future::pending::<Result<(), String>>(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("timed out after 0s"));
    }

    #[tokio::test]
    async fn returns_ready_source() {
        let v = wait_with_timeout("test", Duration::from_secs(5), async {
            sleep(Duration::from_millis(20)).await;
            Ok::<_, String>(42)
        })
        .await
        .unwrap();
        assert_eq!(v, 42);
    }

    #[tokio::test]
    async fn propagates_source_error() {
        let err = wait_with_timeout("test", Duration::from_secs(5), async {
            Err::<(), _>("boom".to_string())
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("boom"));
    }
}
